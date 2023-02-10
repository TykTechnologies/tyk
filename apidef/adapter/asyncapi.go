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

func prepareServerConfig(parsed *asyncapi.AsyncAPI) (map[string]apidef.GraphQLEngineDataSourceConfigKafka, error) {
	serverConfig := make(map[string]apidef.GraphQLEngineDataSourceConfigKafka)
	for name, server := range parsed.Servers {
		c := apidef.GraphQLEngineDataSourceConfigKafka{}
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
		serverConfig[name] = c
	}
	return serverConfig, nil
}

func marshalDataSourceConfig(cfg apidef.GraphQLEngineDataSourceConfigKafka, topic string) ([]byte, error) {
	localConfig := cfg
	localConfig.Topics = append(localConfig.Topics, topic)
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

	serverConfig, err := prepareServerConfig(parsed)
	if err != nil {
		return def, err
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

		// TODO: We only support one data source per field, right?
		if len(channelItem.Servers) == 0 {
			for _, cfg := range serverConfig {
				marshalConfig, err := marshalDataSourceConfig(cfg, channelName)
				if err != nil {
					return def, err
				}
				dataSourceConfig.Config = marshalConfig
				break
			}
		} else {
			for _, server := range channelItem.Servers {
				if cfg, ok := serverConfig[server]; ok {
					marshalConfig, err := marshalDataSourceConfig(cfg, channelName)
					if err != nil {
						return def, err
					}
					dataSourceConfig.Config = marshalConfig
					break
				}
			}
		}

		def.GraphQL.Engine.DataSources = append(def.GraphQL.Engine.DataSources, dataSourceConfig)
	}

	return def, nil
}
