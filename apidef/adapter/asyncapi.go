package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/graphql-go-tools/pkg/astprinter"
	kafkadatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/kafka_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/graphql-translator/asyncapi"
	"github.com/TykTechnologies/tyk/apidef"
)

const (
	KafkaGroupIdKey  = "groupId"
	KafkaClientIdKey = "clientId"
)

func removeCurlyBraces(argument string) string {
	return strings.Map(
		func(r rune) rune {
			if r != '{' && r != '}' {
				return r
			}
			return -1
		},
		argument,
	)
}
func processArgumentSection(input string) string {
	sampleRegexp := regexp.MustCompile("{(.*?)}")
	matches := sampleRegexp.FindAll([]byte(input), -1)
	for _, match := range matches {
		oldArgument := string(match)
		newArgument := fmt.Sprintf("{{.arguments.%s}}", removeCurlyBraces(oldArgument))
		input = strings.ReplaceAll(input, oldArgument, newArgument)
	}
	return input
}

func prepareKafkaDataSourceConfig(parsed *asyncapi.AsyncAPI) (map[string]kafkadatasource.GraphQLSubscriptionOptions, error) {
	serverConfig := make(map[string]kafkadatasource.GraphQLSubscriptionOptions)
	for name, server := range parsed.Servers {
		c := kafkadatasource.GraphQLSubscriptionOptions{}
		switch server.Protocol {
		case "kafka", "kafka-secure":
		default:
			return nil, fmt.Errorf("invalid server protocol: %s", server.Protocol)
		}

		if server.ProtocolVersion != "" {
			c.KafkaVersion = server.ProtocolVersion
		}

		if server.URL == "" {
			return nil, fmt.Errorf("server.URL cannot be empty")
		}
		c.BrokerAddresses = append(c.BrokerAddresses, server.URL)

		// https://github.com/asyncapi/bindings/blob/master/kafka/README.md#operation-binding-object
		kafkaBindings, hasKafkaBindings := server.Bindings[asyncapi.KafkaKey]
		if hasKafkaBindings {
			groupIdBinding, hasGroupId := kafkaBindings[KafkaGroupIdKey]
			if hasGroupId {
				if groupIdBinding.ValueType == jsonparser.String {
					c.GroupID = processArgumentSection(string(groupIdBinding.Value))
				}
			}

			clientIdBinding, hasClientId := kafkaBindings[KafkaClientIdKey]
			if hasClientId {
				if clientIdBinding.ValueType == jsonparser.String {
					c.ClientID = processArgumentSection(string(clientIdBinding.Value))
				}
			}
		}
		serverConfig[name] = c
	}
	return serverConfig, nil
}

func encodeKafkaDataSourceConfig(cfg kafkadatasource.GraphQLSubscriptionOptions, topic string) ([]byte, error) {
	localConfig := cfg
	localConfig.Topics = append(localConfig.Topics, topic)

	localConfig.Sanitize()
	if err := localConfig.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(localConfig)
}

func (a *asyncAPI) prepareGraphQLEngineConfig() error {
	serverConfig, err := prepareKafkaDataSourceConfig(a.document)
	if err != nil {
		return err
	}

	for channelName, channelItem := range a.document.Channels {
		channelName = processArgumentSection(channelName)
		fieldConfig := apidef.GraphQLFieldConfig{
			TypeName:  "Subscription",
			FieldName: channelItem.OperationID,
			Path:      []string{channelItem.OperationID},
		}
		a.apiDefinition.GraphQL.Engine.FieldConfigs = append(a.apiDefinition.GraphQL.Engine.FieldConfigs, fieldConfig)
		rootFields := []apidef.GraphQLTypeFields{
			{
				Type: "Subscription",
				Fields: []string{
					channelItem.OperationID,
				},
			},
		}

		dataSourceConfig := apidef.GraphQLEngineDataSource{
			Kind:       apidef.GraphQLEngineDataSourceKindKafka,
			Name:       fmt.Sprintf("consumer-group:%s", channelItem.OperationID),
			RootFields: rootFields,
		}

		// TODO: We only support one data source per field, right?
		if len(channelItem.Servers) == 0 {
			for _, cfg := range serverConfig {
				marshalConfig, err := encodeKafkaDataSourceConfig(cfg, channelName)
				if err != nil {
					return err
				}
				dataSourceConfig.Config = marshalConfig
				break
			}
		} else {
			for _, server := range channelItem.Servers {
				if cfg, ok := serverConfig[server]; ok {
					encodedConfig, err := encodeKafkaDataSourceConfig(cfg, channelName)
					if err != nil {
						return err
					}
					dataSourceConfig.Config = encodedConfig
					break
				}
			}
		}

		a.apiDefinition.GraphQL.Engine.DataSources = append(a.apiDefinition.GraphQL.Engine.DataSources, dataSourceConfig)
	}

	return nil
}

func (a *asyncAPI) Import() (*apidef.APIDefinition, error) {
	document, err := asyncapi.ParseAsyncAPIDocument(a.input)
	if err != nil {
		return nil, err
	}

	a.document = document
	a.apiDefinition = newApiDefinition(document.Info.Title, a.orgId)

	if err := a.prepareGraphQLEngineConfig(); err != nil {
		return nil, err
	}

	// We iterate over the maps to create a new API definition. This leads to the random placement of
	// items in various arrays in the resulting JSON document. In order to test the AsyncAPI converter
	// with fixtures and prevent randomness, we sort various data structures here.
	sortFieldConfigsByName(a.apiDefinition)
	sortDataSourcesByName(a.apiDefinition)

	gqlDocument := asyncapi.ImportParsedAsyncAPIDocument(a.document, a.report)
	if a.report.HasErrors() {
		return nil, a.report
	}

	w := &bytes.Buffer{}
	err = astprinter.PrintIndent(gqlDocument, nil, []byte("  "), w)
	if err != nil {
		return nil, err
	}
	a.apiDefinition.GraphQL.Schema = w.String()

	return a.apiDefinition, nil
}

type asyncAPI struct {
	orgId         string
	input         []byte
	report        *operationreport.Report
	apiDefinition *apidef.APIDefinition
	document      *asyncapi.AsyncAPI
}

func NewAsyncAPIAdapter(orgId string, input []byte) ImportAdapter {
	return &asyncAPI{
		orgId:  orgId,
		input:  input,
		report: &operationreport.Report{},
	}
}

var _ ImportAdapter = (*asyncAPI)(nil)
