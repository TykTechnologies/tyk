package enginev3

import (
	"encoding/json"
	"net/http"
	"strconv"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	kafkadatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/kafka_datasource"
	restdatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/staticdatasource"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
)

type UniversalDataGraph struct {
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	Schema          *graphql.Schema

	subscriptionClientFactory graphqldatasource.GraphQLSubscriptionClientFactory
}

func (u *UniversalDataGraph) EngineConfigV3() (*graphql.EngineV2Configuration, error) {
	var err error
	if u.Schema == nil {
		// The federation-aware schema augmentation is performed via the
		// registered FederationProvider (EE only). CE's no-op provider returns
		// the schema unchanged.
		schemaStr := u.ApiDefinition.GraphQL.Schema
		schemaStr, err = GetFederationProvider().AugmentSchema(schemaStr, u.ApiDefinition.GraphQL.ExecutionMode)
		if err != nil {
			return nil, err
		}
		u.Schema, err = parseSchema(schemaStr)
		if err != nil {
			return nil, err
		}
	}

	conf := graphql.NewEngineV2Configuration(u.Schema)
	conf.EnableSingleFlight(false)

	fieldConfigs := u.engineConfigV2FieldConfigs()
	datsSources, err := u.engineConfigV2DataSources()
	if err != nil {
		return nil, err
	}

	// Federation hooks. The provider is registered in EE/dev builds via
	// `gateway/mw_graphql_federation_ee.go::init`. CE builds use the no-op
	// provider, which returns an empty entities data source (Factory == nil)
	// and the customer's raw SDL — so the federation-internal data sources are
	// not appended in CE.
	provider := GetFederationProvider()

	federatedSchemaSDL := string(u.Schema.Document())
	entitiesDS, err := provider.BuildEntitiesDataSource(federatedSchemaSDL, u.ApiDefinition, u.HttpClient)
	if err != nil {
		return nil, err
	}

	if entitiesDS.Factory != nil {
		datsSources = append(datsSources, entitiesDS)

		// Add service datasource. ChildNodes for `_Service.sdl` are populated below by
		// determineChildNodes against the federation-augmented schema, so the planner
		// knows this data source can resolve `sdl` selections under `_service`.
		serviceDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"_service"},
				},
			},
			Factory: &staticdatasource.Factory{},
			Custom: staticdatasource.ConfigJSON(staticdatasource.Configuration{
				// Emit the federation-aware SDL: ServiceSDL preserves an explicit
				// `@link` if the customer wrote one, auto-prepends a v2 `@link`
				// when the SDL has `@key` but no version declaration, or returns
				// the SDL untouched when there's nothing federation-shaped. For
				// federation subgraphs it also strips any Query field that isn't
				// backed by a data source — those would otherwise be routed to
				// Tyk by Apollo Router and fail with "Failed to fetch from
				// Subgraph at path 'query.<field>'".
				Data: `{"_service":{"sdl":` + strconv.Quote(provider.ServiceSDL(u.ApiDefinition.GraphQL.Schema, u.ApiDefinition.GraphQL.Engine.DataSources)) + `}}`,
			}),
		}
		datsSources = append(datsSources, serviceDataSource)

		// Auto-populate ChildNodes for the entities and service data sources by
		// walking the federation-augmented schema. We slice the just-appended
		// federation-internal data sources in place — `determineChildNodes`
		// mutates `ChildNodes` on each element, and the sub-slice shares
		// backing storage with `datsSources` so the mutations propagate. The
		// user data sources were already processed inside
		// engineConfigV2DataSources; re-running them here would duplicate
		// entries.
		if err := u.determineChildNodes(datsSources[len(datsSources)-2:]); err != nil {
			return nil, err
		}
	}

	conf.SetFieldConfigurations(fieldConfigs)
	conf.SetDataSources(datsSources)

	return &conf, nil
}

func (u *UniversalDataGraph) engineConfigV2FieldConfigs() (planFieldConfigs plan.FieldConfigurations) {
	for _, fc := range u.ApiDefinition.GraphQL.Engine.FieldConfigs {
		planFieldConfig := plan.FieldConfiguration{
			TypeName:              fc.TypeName,
			FieldName:             fc.FieldName,
			DisableDefaultMapping: fc.DisableDefaultMapping,
			Path:                  fc.Path,
		}

		planFieldConfigs = append(planFieldConfigs, planFieldConfig)
	}

	generatedArgs := u.Schema.GetAllFieldArguments(graphql.NewSkipReservedNamesFunc())
	generatedArgsAsLookupMap := graphql.CreateTypeFieldArgumentsLookupMap(generatedArgs)
	u.engineConfigV2Arguments(&planFieldConfigs, generatedArgsAsLookupMap)

	return planFieldConfigs
}

func (u *UniversalDataGraph) engineConfigV2DataSources() (planDataSources []plan.DataSourceConfiguration, err error) {
	for _, ds := range u.ApiDefinition.GraphQL.Engine.DataSources {
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

			planDataSource.Factory = &restdatasource.Factory{
				Client: u.HttpClient,
			}

			urlWithoutQueryParams, queryConfigs, err := extractURLQueryParamsForEngineV2(restConfig.URL, restConfig.Query)
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = restdatasource.ConfigJSON(restdatasource.Configuration{
				Fetch: restdatasource.FetchConfiguration{
					URL:    urlWithoutQueryParams,
					Method: restConfig.Method,
					Body:   restConfig.Body,
					Query:  queryConfigs,
					Header: ConvertApiDefinitionHeadersToHttpHeaders(restConfig.Headers),
				},
			})

		case apidef.GraphQLEngineDataSourceKindGraphQL:
			var graphqlConfig apidef.GraphQLEngineDataSourceConfigGraphQL
			err = json.Unmarshal(ds.Config, &graphqlConfig)
			if err != nil {
				return nil, err
			}

			if graphqlConfig.HasOperation {
				planDataSource.Factory = &restdatasource.Factory{
					Client: u.HttpClient,
				}
				planDataSource.Custom, err = generateRestDataSourceFromGraphql(graphqlConfig)
				if err != nil {
					return nil, err
				}
				break
			}

			planDataSource.Factory, err = createGraphQLDataSourceFactory(createGraphQLDataSourceFactoryParams{
				graphqlConfig:             graphqlConfig,
				subscriptionClientFactory: subscriptionClientFactoryOrDefault(u.subscriptionClientFactory),
				httpClient:                u.HttpClient,
				streamingClient:           u.StreamingClient,
			})
			if err != nil {
				return nil, err
			}

			planDataSource.Custom = graphqldatasource.ConfigJson(graphqlDataSourceConfiguration(
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

			planDataSource.Factory = &kafkadatasource.Factory{}
			planDataSource.Custom = kafkadatasource.ConfigJSON(kafkadatasource.Configuration{
				Subscription: kafkadatasource.SubscriptionConfiguration{
					BrokerAddresses:      kafkaConfig.BrokerAddresses,
					Topics:               kafkaConfig.Topics,
					GroupID:              kafkaConfig.GroupID,
					ClientID:             kafkaConfig.ClientID,
					KafkaVersion:         kafkaConfig.KafkaVersion,
					StartConsumingLatest: kafkaConfig.StartConsumingLatest,
					BalanceStrategy:      kafkaConfig.BalanceStrategy,
					IsolationLevel:       kafkaConfig.IsolationLevel,
					SASL: kafkadatasource.SASL{
						Enable:   kafkaConfig.SASL.Enable,
						User:     kafkaConfig.SASL.User,
						Password: kafkaConfig.SASL.Password,
					},
				},
			})
		}

		planDataSources = append(planDataSources, planDataSource)
	}

	err = u.determineChildNodes(planDataSources)
	return planDataSources, err
}

func (u *UniversalDataGraph) engineConfigV2Arguments(fieldConfs *plan.FieldConfigurations, generatedArgs map[graphql.TypeFieldLookupKey]graphql.TypeFieldArguments) {
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

func (u *UniversalDataGraph) determineChildNodes(planDataSources []plan.DataSourceConfiguration) error {
	for i := range planDataSources {
		for j := range planDataSources[i].RootNodes {
			typeName := planDataSources[i].RootNodes[j].TypeName
			for k := range planDataSources[i].RootNodes[j].FieldNames {
				fieldName := planDataSources[i].RootNodes[j].FieldNames[k]
				typeFields := u.Schema.GetAllNestedFieldChildrenFromTypeField(typeName, fieldName, graphql.NewIsDataSourceConfigV2RootFieldSkipFunc(planDataSources))

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
