package adapter

import (
	"errors"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	restDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"

	"github.com/TykTechnologies/tyk/apidef"
)

type createGraphQLDataSourceFactoryParams struct {
	graphqlConfig             apidef.GraphQLEngineDataSourceConfigGraphQL
	subscriptionClientFactory graphqlDataSource.GraphQLSubscriptionClientFactory
	httpClient                *http.Client
	streamingClient           *http.Client
}

func graphqlDataSourceConfiguration(url string, method string, headers map[string]string, subscriptionType apidef.SubscriptionType) graphqlDataSource.Configuration {
	dataSourceHeaders := make(map[string]string)
	for name, value := range headers {
		dataSourceHeaders[name] = value
	}

	if strings.HasPrefix(url, "tyk://") {
		url = strings.ReplaceAll(url, "tyk://", "http://")
		dataSourceHeaders[apidef.TykInternalApiHeader] = "true"
	}

	cfg := graphqlDataSource.Configuration{
		Fetch: graphqlDataSource.FetchConfiguration{
			URL:    url,
			Method: method,
			Header: convertApiDefinitionHeadersToHttpHeaders(dataSourceHeaders),
		},
		Subscription: graphqlDataSource.SubscriptionConfiguration{
			URL:    url,
			UseSSE: subscriptionType == apidef.GQLSubscriptionSSE,
		},
	}

	return cfg
}

func createArgumentConfigurationsForArgumentNames(argumentNames ...string) plan.ArgumentsConfigurations {
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

func extractURLQueryParamsForEngineV2(url string, providedApiDefQueries []apidef.QueryVariable) (urlWithoutParams string, engineV2Queries []restDataSource.QueryConfiguration, err error) {
	urlParts := strings.Split(url, "?")
	urlWithoutParams = urlParts[0]

	queryPart := ""
	if len(urlParts) == 2 {
		queryPart = urlParts[1]
	}
	// Parse only query part as URL could contain templating {{.argument.id}} which should not be escaped
	values, err := neturl.ParseQuery(queryPart)
	if err != nil {
		return "", nil, err
	}

	engineV2Queries = make([]restDataSource.QueryConfiguration, 0)
	appendURLQueryParamsToEngineV2Queries(&engineV2Queries, values)
	appendApiDefQueriesConfigToEngineV2Queries(&engineV2Queries, providedApiDefQueries)

	if len(engineV2Queries) == 0 {
		return urlWithoutParams, nil, nil
	}

	return urlWithoutParams, engineV2Queries, nil
}

func appendURLQueryParamsToEngineV2Queries(engineV2Queries *[]restDataSource.QueryConfiguration, queryValues neturl.Values) {
	for queryKey, queryValue := range queryValues {
		*engineV2Queries = append(*engineV2Queries, restDataSource.QueryConfiguration{
			Name:  queryKey,
			Value: strings.Join(queryValue, ","),
		})
	}

	sort.Slice(*engineV2Queries, func(i, j int) bool {
		return (*engineV2Queries)[i].Name < (*engineV2Queries)[j].Name
	})
}

func appendApiDefQueriesConfigToEngineV2Queries(engineV2Queries *[]restDataSource.QueryConfiguration, apiDefQueries []apidef.QueryVariable) {
	if len(apiDefQueries) == 0 {
		return
	}

	for _, apiDefQueryVar := range apiDefQueries {
		engineV2Query := restDataSource.QueryConfiguration{
			Name:  apiDefQueryVar.Name,
			Value: apiDefQueryVar.Value,
		}

		*engineV2Queries = append(*engineV2Queries, engineV2Query)
	}
}

func createGraphQLDataSourceFactory(params createGraphQLDataSourceFactoryParams) (*graphqlDataSource.Factory, error) {
	factory := &graphqlDataSource.Factory{
		HTTPClient:      params.httpClient,
		StreamingClient: params.streamingClient,
	}

	wsProtocol := graphqlDataSourceWebSocketProtocol(params.graphqlConfig.SubscriptionType)
	graphqlSubscriptionClient := params.subscriptionClientFactory.NewSubscriptionClient(
		params.httpClient,
		params.streamingClient,
		nil,
		graphqlDataSource.WithWSSubProtocol(wsProtocol),
	)

	subscriptionClient, ok := graphqlSubscriptionClient.(*graphqlDataSource.SubscriptionClient)
	if !ok {
		return nil, errors.New("incorrect SubscriptionClient has been created")
	}
	factory.SubscriptionClient = subscriptionClient
	return factory, nil
}
