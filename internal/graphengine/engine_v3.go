package graphengine

import (
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"
	"net/http"
)

type EngineV3 struct {
	engine *graphql.ExecutionEngineV2
	schema *graphql.Schema
}

type EngineV3Options struct {
	Logger        *logrus.Logger
	Schema        *graphql.Schema
	ApiDefinition *apidef.APIDefinition
	HttpClient    *http.Client
}

func NewEngineV3(options EngineV3Options) (*EngineV3, error) {
	logger := createAbstractLogrusLogger(options.Logger)
	gqlTools := graphqlGoToolsV2{}

	var parsedSchema = options.Schema
	if parsedSchema == nil {
		var err error
		parsedSchema, err = gqlTools.parseSchema(options.ApiDefinition.GraphQL.Schema)
		if err != nil {
			logger.Error("error on schema parsing", abstractlogger.Error(err))
			return nil, err
		}
	}
	return nil, nil
}

func (e *EngineV3) Version() EngineVersion {
	return EngineVersionV3
}

func (e *EngineV3) HasSchema() bool {
	//TODO implement me
	panic("implement me")
}

func (e *EngineV3) Cancel() {
	//TODO implement me
	panic("implement me")
}

func (e *EngineV3) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e *EngineV3) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e *EngineV3) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e *EngineV3) HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	//TODO implement me
	panic("implement me")
}
