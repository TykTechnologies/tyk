package graphengine

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
)

type EngineV2 struct {
	HttpClient      *http.Client
	StreamingClient *http.Client
}

type EngineV2Options struct {
	logger          *logrus.Logger
	apiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
}

func NewEngineV2(options EngineV2Options) (*EngineV2, error) {
	return &EngineV2{
		HttpClient:      options.HttpClient,
		StreamingClient: options.StreamingClient,
	}, nil
}

func (e EngineV2) HasSchema() bool {
	//TODO implement me
	panic("implement me")
}

func (e EngineV2) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e EngineV2) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e EngineV2) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e EngineV2) HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	//TODO implement me
	panic("implement me")
}

// Interface Guard
var _ Engine = (*EngineV2)(nil)
