package graphengine

import (
	"io"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

type engineV2Mocks struct {
	controller             *gomock.Controller
	requestProcessor       *MockGraphQLRequestProcessor
	complexityChecker      *MockComplexityChecker
	granularAccessChecker  *MockGranularAccessChecker
	reverseProxyPreHandler *MockReverseProxyPreHandler
}

func TestEngineV2_HasSchema(t *testing.T) {
	t.Run("should be true if engine has a schema", func(t *testing.T) {
		engine, _ := newTestEngineV2(t)
		assert.True(t, engine.HasSchema())
	})
	t.Run("should be false if engine has no schema", func(t *testing.T) {
		engine := EngineV2{
			Schema: nil,
		}
		assert.False(t, engine.HasSchema())
	})
}

type testEngineV2Options struct {
	targetURL     string
	apiDefinition *apidef.APIDefinition
	otelConfig    *EngineV2OTelConfig
}

type testEngineV2Option func(*testEngineV2Options)

func withTargetURLTestEngineV2(targetURL string) testEngineV2Option {
	return func(options *testEngineV2Options) {
		options.targetURL = targetURL
	}
}

func withApiDefinitionTestEngineV2(apiDefinition *apidef.APIDefinition) testEngineV2Option {
	return func(options *testEngineV2Options) {
		options.apiDefinition = apiDefinition
	}
}

func withOpenTelemetryTestEngineV2(otelConfig *EngineV2OTelConfig) testEngineV2Option {
	return func(options *testEngineV2Options) {
		options.otelConfig = otelConfig
	}
}

func newTestEngineV2(t *testing.T, options ...testEngineV2Option) (*EngineV2, engineV2Mocks) {
	definedOptions := testEngineV2Options{
		apiDefinition: newTestProxyOnlyApiDefinitionV2(),
	}

	for _, option := range options {
		option(&definedOptions)
	}

	logrusLogger := logrus.New()
	logrusLogger.SetOutput(io.Discard)

	ctrl := gomock.NewController(t)
	mocks := engineV2Mocks{
		controller:             ctrl,
		requestProcessor:       NewMockGraphQLRequestProcessor(ctrl),
		complexityChecker:      NewMockComplexityChecker(ctrl),
		granularAccessChecker:  NewMockGranularAccessChecker(ctrl),
		reverseProxyPreHandler: NewMockReverseProxyPreHandler(ctrl),
	}

	engineV2, err := NewEngineV2(EngineV2Options{
		Logger:                  logrusLogger,
		ApiDefinition:           definedOptions.apiDefinition,
		HttpClient:              &http.Client{},
		StreamingClient:         &http.Client{},
		OpenTelemetry:           &EngineV2OTelConfig{},
		BeforeFetchHook:         nil,
		AfterFetchHook:          nil,
		WebsocketOnBeforeStart:  nil,
		ContextStoreRequest:     nil,
		ContextRetrieveRequest:  nil,
		EngineTransportModifier: nil,
	})
	require.NoError(t, err)

	// Set mocks
	engineV2.graphqlRequestProcessor = mocks.requestProcessor
	engineV2.complexityChecker = mocks.complexityChecker
	engineV2.granularAccessChecker = mocks.granularAccessChecker
	engineV2.reverseProxyPreHandler = mocks.reverseProxyPreHandler

	return engineV2, mocks
}

func newTestProxyOnlyApiDefinitionV2() *apidef.APIDefinition {
	return &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Enabled:       true,
			ExecutionMode: apidef.GraphQLExecutionModeProxyOnly,
			Version:       apidef.GraphQLConfigVersion2,
			Schema:        testSchemaEngineV2,
		},
	}
}

var testSchemaEngineV2 = `
type Query {
	hello: String
	helloName(name: String!): String
}
`
