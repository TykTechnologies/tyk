package graphql

import (
	"net/http"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	graphqlDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
)

const (
	DefaultFlushIntervalInMilliseconds = 1000
)

type EngineV2Configuration struct {
	schema                   *Schema
	plannerConfig            plan.Configuration
	websocketBeforeStartHook WebsocketBeforeStartHook
	dataLoaderConfig         dataLoaderConfig
}

func NewEngineV2Configuration(schema *Schema) EngineV2Configuration {
	return EngineV2Configuration{
		schema: schema,
		plannerConfig: plan.Configuration{
			DefaultFlushIntervalMillis: DefaultFlushIntervalInMilliseconds,
			DataSources:                []plan.DataSourceConfiguration{},
			Fields:                     plan.FieldConfigurations{},
		},
		dataLoaderConfig: dataLoaderConfig{
			EnableSingleFlightLoader: false,
			EnableDataLoader:         false,
		},
	}
}

type dataLoaderConfig struct {
	EnableSingleFlightLoader bool
	EnableDataLoader         bool
}

func (e *EngineV2Configuration) AddDataSource(dataSource plan.DataSourceConfiguration) {
	e.plannerConfig.DataSources = append(e.plannerConfig.DataSources, dataSource)
}

func (e *EngineV2Configuration) SetDataSources(dataSources []plan.DataSourceConfiguration) {
	e.plannerConfig.DataSources = dataSources
}

func (e *EngineV2Configuration) AddFieldConfiguration(fieldConfig plan.FieldConfiguration) {
	e.plannerConfig.Fields = append(e.plannerConfig.Fields, fieldConfig)
}

func (e *EngineV2Configuration) SetFieldConfigurations(fieldConfigs plan.FieldConfigurations) {
	e.plannerConfig.Fields = fieldConfigs
}

func (e *EngineV2Configuration) DataSources() []plan.DataSourceConfiguration {
	return e.plannerConfig.DataSources
}

func (e *EngineV2Configuration) FieldConfigurations() plan.FieldConfigurations {
	return e.plannerConfig.Fields
}

func (e *EngineV2Configuration) EnableDataLoader(enable bool) {
	e.dataLoaderConfig.EnableDataLoader = enable
}

// SetWebsocketBeforeStartHook - sets before start hook which will be called before processing any operation sent over websockets
func (e *EngineV2Configuration) SetWebsocketBeforeStartHook(hook WebsocketBeforeStartHook) {
	e.websocketBeforeStartHook = hook
}

type graphqlDataSourceV2Generator struct {
	document *ast.Document
}

func newGraphQLDataSourceV2Generator(document *ast.Document) *graphqlDataSourceV2Generator {
	return &graphqlDataSourceV2Generator{
		document: document,
	}
}

func (d *graphqlDataSourceV2Generator) Generate(config graphqlDataSource.Configuration, batchFactory resolve.DataSourceBatchFactory, httpClient *http.Client) plan.DataSourceConfiguration {
	var planDataSource plan.DataSourceConfiguration
	extractor := plan.NewLocalTypeFieldExtractor(d.document)
	planDataSource.RootNodes, planDataSource.ChildNodes = extractor.GetAllNodes()

	factory := &graphqlDataSource.Factory{
		HTTPClient:   httpClient,
		BatchFactory: batchFactory,
	}

	planDataSource.Factory = factory
	planDataSource.Custom = graphqlDataSource.ConfigJson(config)

	return planDataSource
}

type graphqlFieldConfigurationsV2Generator struct {
	schema *Schema
}

func newGraphQLFieldConfigsV2Generator(schema *Schema) *graphqlFieldConfigurationsV2Generator {
	return &graphqlFieldConfigurationsV2Generator{
		schema: schema,
	}
}

func (g *graphqlFieldConfigurationsV2Generator) Generate(predefinedFieldConfigs ...plan.FieldConfiguration) plan.FieldConfigurations {
	var planFieldConfigs plan.FieldConfigurations
	if len(predefinedFieldConfigs) > 0 {
		planFieldConfigs = predefinedFieldConfigs
	}

	generatedArgs := g.schema.GetAllFieldArguments(NewSkipReservedNamesFunc())
	generatedArgsAsLookupMap := CreateTypeFieldArgumentsLookupMap(generatedArgs)
	g.engineConfigArguments(&planFieldConfigs, generatedArgsAsLookupMap)

	return planFieldConfigs
}

func (g *graphqlFieldConfigurationsV2Generator) engineConfigArguments(fieldConfs *plan.FieldConfigurations, generatedArgs map[TypeFieldLookupKey]TypeFieldArguments) {
	for i := range *fieldConfs {
		if len(generatedArgs) == 0 {
			return
		}

		lookupKey := CreateTypeFieldLookupKey((*fieldConfs)[i].TypeName, (*fieldConfs)[i].FieldName)
		currentArgs, exists := generatedArgs[lookupKey]
		if !exists {
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

func (g *graphqlFieldConfigurationsV2Generator) createArgumentConfigurationsForArgumentNames(argumentNames []string) plan.ArgumentsConfigurations {
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
