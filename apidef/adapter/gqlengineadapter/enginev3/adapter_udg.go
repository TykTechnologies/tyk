package enginev3

import (
	"encoding/json"
	"net/http"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	kafkadatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/kafka_datasource"
	restdatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/rest_datasource"
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
		u.Schema, err = parseSchema(u.ApiDefinition.GraphQL.Schema)
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
