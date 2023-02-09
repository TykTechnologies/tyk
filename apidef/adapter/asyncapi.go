package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astprinter"
	"github.com/TykTechnologies/graphql-go-tools/pkg/asyncapi"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
	"github.com/TykTechnologies/tyk/apidef"
)

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

	serverConfig := make(map[string]apidef.GraphQLEngineDataSourceConfigKafka)
	for name, server := range parsed.Servers {
		c := apidef.GraphQLEngineDataSourceConfigKafka{}
		switch server.Protocol {
		case "kafka", "kafka-secure":
		default:
			return def, fmt.Errorf("invalid server protocol: %s", server.Protocol)
		}

		if server.ProtocolVersion != "" {
			c.KafkaVersion = server.ProtocolVersion
		}

		if server.URL == "" {
			return def, fmt.Errorf("server.URL cannot be empty")
		}
		c.BrokerAddresses = append(c.BrokerAddresses, server.URL)
		serverConfig[name] = c
	}

	for channelName, channelItem := range parsed.Channels {
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

		if len(channelItem.Servers) == 0 {
			for _, cfg := range serverConfig {
				localConfig := cfg
				localConfig.Topics = append(localConfig.Topics, channelName)
				encodedConfig, err := json.Marshal(localConfig)
				if err != nil {
					return def, err
				}
				dataSourceConfig.Config = encodedConfig
				// TODO: We only support one data source per field, right?
				break
			}
		} else {
			for _, server := range channelItem.Servers {
				if cfg, ok := serverConfig[server]; ok {
					localConfig := cfg
					localConfig.Topics = append(localConfig.Topics, channelName)
					encodedConfig, err := json.Marshal(localConfig)
					if err != nil {
						return def, err
					}
					dataSourceConfig.Config = encodedConfig
					// TODO: We only support one data source per field, right?
					break
				}
			}
		}

		def.GraphQL.Engine.DataSources = append(def.GraphQL.Engine.DataSources, dataSourceConfig)
	}

	return def, nil
}
