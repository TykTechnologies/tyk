package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/TykTechnologies/graphql-go-tools/pkg/astprinter"
	"github.com/TykTechnologies/graphql-go-tools/pkg/asyncapi"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/kafka_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/buger/jsonparser"
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

func prepareKafkaDataSourceConfig(parsed *asyncapi.AsyncAPI) (map[string]kafka_datasource.GraphQLSubscriptionOptions, error) {
	serverConfig := make(map[string]kafka_datasource.GraphQLSubscriptionOptions)
	for name, server := range parsed.Servers {
		c := kafka_datasource.GraphQLSubscriptionOptions{}
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
			groupIdBinding, hasGroupId := kafkaBindings["groupId"]
			if hasGroupId {
				if groupIdBinding.ValueType == jsonparser.String {
					c.GroupID = processArgumentSection(string(groupIdBinding.Value))
				}
			}

			clientIdBinding, hasClientId := kafkaBindings["clientId"]
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

func encodeKafkaDataSourceConfig(cfg kafka_datasource.GraphQLSubscriptionOptions, topic string) ([]byte, error) {
	localConfig := cfg
	localConfig.Topics = append(localConfig.Topics, topic)

	localConfig.Sanitize()
	if err := localConfig.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(localConfig)
}

func ImportAsyncAPIDocument(input []byte) (apidef.APIDefinition, error) {
	def := apidef.DummyAPI()

	parsed, err := asyncapi.ParseAsyncAPIDocument(input)
	if err != nil {
		return def, err
	}

	report := operationreport.Report{}
	doc := asyncapi.ImportParsedAsyncAPIDocument(parsed, &report)
	if report.HasErrors() {
		return def, report
	}

	w := &bytes.Buffer{}
	err = astprinter.PrintIndent(doc, nil, []byte("  "), w)
	if err != nil {
		return def, err
	}

	def.Name = fmt.Sprintf("%s - %s", parsed.Info.Title, parsed.Info.Version)
	def.GraphQL.Enabled = true
	def.Active = true
	def.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
	def.GraphQL.Schema = w.String()

	serverConfig, err := prepareKafkaDataSourceConfig(parsed)
	if err != nil {
		return def, err
	}

	for channelName, channelItem := range parsed.Channels {
		channelName = processArgumentSection(channelName)
		fieldConfig := apidef.GraphQLFieldConfig{
			TypeName:  "Subscription",
			FieldName: channelItem.OperationID,
			Path:      []string{channelItem.OperationID},
		}
		def.GraphQL.Engine.FieldConfigs = append(def.GraphQL.Engine.FieldConfigs, fieldConfig)
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
					return def, err
				}
				dataSourceConfig.Config = marshalConfig
				break
			}
		} else {
			for _, server := range channelItem.Servers {
				if cfg, ok := serverConfig[server]; ok {
					encodedConfig, err := encodeKafkaDataSourceConfig(cfg, channelName)
					if err != nil {
						return def, err
					}
					dataSourceConfig.Config = encodedConfig
					break
				}
			}
		}

		def.GraphQL.Engine.DataSources = append(def.GraphQL.Engine.DataSources, dataSourceConfig)
	}

	// We iterate over the maps to create a new API definition. This leads to the random placement of
	// items in various arrays in the resulting JSON document. In order to test the AsyncAPI converter
	// with fixtures and prevent randomness, we sort various data structures here.

	sort.Slice(def.GraphQL.Engine.FieldConfigs, func(i, j int) bool {
		return def.GraphQL.Engine.FieldConfigs[i].FieldName < def.GraphQL.Engine.FieldConfigs[j].FieldName
	})

	sort.Slice(def.GraphQL.Engine.DataSources, func(i, j int) bool {
		return def.GraphQL.Engine.DataSources[i].Name < def.GraphQL.Engine.DataSources[j].Name
	})

	return def, nil
}
