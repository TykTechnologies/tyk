package graphql

import (
	"net/http"
	"time"

	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	graphqlDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
)

type proxyEngineConfigFactoryOptions struct {
	httpClient *http.Client
}

type ProxyEngineConfigFactoryOption func(options *proxyEngineConfigFactoryOptions)

func WithProxyHttpClient(client *http.Client) ProxyEngineConfigFactoryOption {
	return func(options *proxyEngineConfigFactoryOptions) {
		options.httpClient = client
	}
}

// ProxyUpstreamConfig holds configuration to configure a single data source to a single upstream.
type ProxyUpstreamConfig struct {
	URL           string
	Method        string
	StaticHeaders http.Header
}

// ProxyEngineConfigFactory is used to create a v2 engine config with a single upstream and a single data source for this upstream.
type ProxyEngineConfigFactory struct {
	httpClient          *http.Client
	schema              *Schema
	proxyUpstreamConfig ProxyUpstreamConfig
	batchFactory        resolve.DataSourceBatchFactory
}

func NewProxyEngineConfigFactory(schema *Schema, proxyUpstreamConfig ProxyUpstreamConfig, batchFactory resolve.DataSourceBatchFactory, opts ...ProxyEngineConfigFactoryOption) *ProxyEngineConfigFactory {
	options := proxyEngineConfigFactoryOptions{
		httpClient: &http.Client{
			Timeout: time.Second * 10,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 1024,
				TLSHandshakeTimeout: 0 * time.Second,
			},
		},
	}

	for _, optFunc := range opts {
		optFunc(&options)
	}

	return &ProxyEngineConfigFactory{
		httpClient:          options.httpClient,
		schema:              schema,
		proxyUpstreamConfig: proxyUpstreamConfig,
		batchFactory:        batchFactory,
	}
}

func (p *ProxyEngineConfigFactory) EngineV2Configuration() (EngineV2Configuration, error) {
	dataSourceConfig := graphqlDataSource.Configuration{
		Fetch: graphqlDataSource.FetchConfiguration{
			URL:    p.proxyUpstreamConfig.URL,
			Method: p.proxyUpstreamConfig.Method,
			Header: p.proxyUpstreamConfig.StaticHeaders,
		},
		Subscription: graphqlDataSource.SubscriptionConfiguration{
			URL: p.proxyUpstreamConfig.URL,
		},
	}

	conf := NewEngineV2Configuration(p.schema)

	rawDoc, report := astparser.ParseGraphqlDocumentBytes(p.schema.rawInput)
	if report.HasErrors() {
		return EngineV2Configuration{}, report
	}

	dataSource := newGraphQLDataSourceV2Generator(&rawDoc).Generate(dataSourceConfig, p.batchFactory, p.httpClient)
	conf.AddDataSource(dataSource)

	fieldConfigs := newGraphQLFieldConfigsV2Generator(p.schema).Generate()
	conf.SetFieldConfigurations(fieldConfigs)

	return conf, nil
}
