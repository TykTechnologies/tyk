package apidef

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/httpclient"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
)

var ErrUnsupportedGraphQLConfigVersion = errors.New("provided version of GraphQL config is not supported for this operation")

type GraphQLConfigAdapter struct {
	config     GraphQLConfig
	httpClient *http.Client
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
			restConfig := GraphQLEngineDataSourceConfigREST{}
			err = json.Unmarshal(ds.Config, &restConfig)
			if err != nil {
				return nil, err
			}

			factory := &rest_datasource.Factory{}
			if g.httpClient != nil {
				factory.Client = httpclient.NewNetHttpClient(g.httpClient)
			}
			planDataSource.Factory = factory

			planDataSource.Custom = rest_datasource.ConfigJSON(rest_datasource.Configuration{
				Fetch: rest_datasource.FetchConfiguration{
					URL:    restConfig.URL,
					Method: restConfig.Method,
				},
			})

		case GraphQLEngineDataSourceKindGraphQL:

			graphqlConfig := GraphQLEngineDataSourceConfigGraphQL{}
			err = json.Unmarshal(ds.Config, &graphqlConfig)
			if err != nil {
				return nil, err
			}

			factory := &graphql_datasource.Factory{}
			if g.httpClient != nil {
				factory.Client = httpclient.NewNetHttpClient(g.httpClient)
			}
			planDataSource.Factory = factory

			planDataSource.Custom = graphql_datasource.ConfigJson(graphql_datasource.Configuration{
				Fetch: graphql_datasource.FetchConfiguration{
					URL:        graphqlConfig.URL,
					HttpMethod: graphqlConfig.Method,
				},
			})
		}

		planDataSources = append(planDataSources, planDataSource)
	}

	err = g.determineChildNodes(&planDataSources)
	return planDataSources, err
}

func (g *GraphQLConfigAdapter) SetHttpClient(httpClient *http.Client) {
	g.httpClient = httpClient
}

func (g *GraphQLConfigAdapter) determineChildNodes(planDataSources *[]plan.DataSourceConfiguration) error {
	schema, report := astparser.ParseGraphqlDocumentString(g.config.Schema)
	if report.HasErrors() {
		return report
	}
	for i := range *planDataSources {
		for j := range (*planDataSources)[i].RootNodes {
			typeName := (*planDataSources)[i].RootNodes[j].TypeName
			for k := range (*planDataSources)[i].RootNodes[j].FieldNames {
				fieldName := (*planDataSources)[i].RootNodes[j].FieldNames[k]
				children := g.findFieldChildren(typeName, fieldName, &schema, *planDataSources)
				(*planDataSources)[i].ChildNodes = append((*planDataSources)[i].ChildNodes, children...)
			}
		}
	}
	return nil
}

func (g *GraphQLConfigAdapter) findFieldChildren(typeName, fieldName string, schema *ast.Document, dataSources []plan.DataSourceConfiguration) []plan.TypeField {
	node, exists := schema.Index.FirstNodeByNameStr(typeName)
	if !exists {
		return nil
	}
	var fields []int
	switch node.Kind {
	case ast.NodeKindObjectTypeDefinition:
		fields = schema.ObjectTypeDefinitions[node.Ref].FieldsDefinition.Refs
	case ast.NodeKindInterfaceTypeDefinition:
		fields = schema.InterfaceTypeDefinitions[node.Ref].FieldsDefinition.Refs
	default:
		return nil
	}
	if len(fields) == 0 {
		return nil
	}
	for _, ref := range fields {
		if fieldName == schema.FieldDefinitionNameString(ref) {
			fieldTypeName := schema.FieldDefinitionTypeNode(ref).NameString(schema)
			childNodes := []plan.TypeField{}
			g.findNestedFieldChildren(fieldTypeName, schema, dataSources, &childNodes)
			return childNodes
		}
	}

	return nil
}

func (g *GraphQLConfigAdapter) findNestedFieldChildren(typeName string, schema *ast.Document, dataSources []plan.DataSourceConfiguration, childNodes *[]plan.TypeField) {
	node, exists := schema.Index.FirstNodeByNameStr(typeName)
	if !exists {
		return
	}
	var fields []int
	switch node.Kind {
	case ast.NodeKindObjectTypeDefinition:
		fields = schema.ObjectTypeDefinitions[node.Ref].FieldsDefinition.Refs
	case ast.NodeKindInterfaceTypeDefinition:
		fields = schema.InterfaceTypeDefinitions[node.Ref].FieldsDefinition.Refs
	default:
		return
	}
	if len(fields) == 0 {
		return
	}
	for _, ref := range fields {
		fieldName := schema.FieldDefinitionNameString(ref)
		if g.isRootField(typeName, fieldName, dataSources) {
			continue
		}
		g.putChildNode(childNodes, typeName, fieldName)
		fieldTypeName := schema.FieldDefinitionTypeNode(ref).NameString(schema)
		g.findNestedFieldChildren(fieldTypeName, schema, dataSources, childNodes)
	}
	return
}

func (g *GraphQLConfigAdapter) isRootField(typeName, fieldName string, dataSources []plan.DataSourceConfiguration) bool {
	for i := range dataSources {
		for j := range dataSources[i].RootNodes {
			if typeName != dataSources[i].RootNodes[j].TypeName {
				continue
			}
			for k := range dataSources[i].RootNodes[j].FieldNames {
				if fieldName == dataSources[i].RootNodes[j].FieldNames[k] {
					return true
				}
			}
		}
	}
	return false
}

func (g *GraphQLConfigAdapter) putChildNode(nodes *[]plan.TypeField, typeName, fieldName string) {
	for i := range *nodes {
		if typeName != (*nodes)[i].TypeName {
			continue
		}
		for j := range (*nodes)[i].FieldNames {
			if fieldName == (*nodes)[i].FieldNames[j] {
				return
			}
		}
		(*nodes)[i].FieldNames = append((*nodes)[i].FieldNames, fieldName)
		return
	}
	*nodes = append(*nodes, plan.TypeField{
		TypeName:   typeName,
		FieldNames: []string{fieldName},
	})
}
