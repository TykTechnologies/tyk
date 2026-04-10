package graphengine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/otel"
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
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		assert.True(t, engine.HasSchema())
	})
	t.Run("should be false if engine has no schema", func(t *testing.T) {
		engine := EngineV2{
			Schema: nil,
		}
		assert.False(t, engine.HasSchema())
	})
}

func TestEngineV2_ProcessAndStoreGraphQLRequest(t *testing.T) {
	t.Run("should return error and Bad Request if it can't parse the gql request", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte("invalid gql request")))
		require.NoError(t, err)

		err, statusCode := engine.ProcessAndStoreGraphQLRequest(nil, request)
		assert.Equal(t, 400, statusCode)
		assert.Error(t, err)
	})

	t.Run("should return no error and success if no error occurs", func(t *testing.T) {
		var expectedGraphQLRequest *graphql.Request
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		engine.ctxStoreRequestFunc = func(r *http.Request, gqlRequest *graphql.Request) {
			expectedGraphQLRequest = gqlRequest
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := &httptest.ResponseRecorder{}

		mocks.requestProcessor.EXPECT().ProcessRequest(gomock.Eq(request.Context()), gomock.Eq(recorder), gomock.Eq(request)).
			Return(nil, 200)

		err, statusCode := engine.ProcessAndStoreGraphQLRequest(recorder, request)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
		assert.Equal(t, expectedGraphQLRequest, &graphql.Request{
			Query: "query { hello }",
		})
	})

	t.Run("should return no error and success if no error occurs and OTel without detailedTracing is enabled", func(t *testing.T) {
		var expectedGraphQLRequest *graphql.Request
		engine, mocks := newTestEngineV2(t, withOpenTelemetryTestEngineV2(false))
		defer mocks.controller.Finish()
		engine.ctxStoreRequestFunc = func(r *http.Request, gqlRequest *graphql.Request) {
			expectedGraphQLRequest = gqlRequest
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := &httptest.ResponseRecorder{}

		mocks.requestProcessor.EXPECT().ProcessRequest(gomock.Eq(request.Context()), gomock.Eq(recorder), gomock.Eq(request)).
			Return(nil, 200)

		err, statusCode := engine.ProcessAndStoreGraphQLRequest(recorder, request)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
		assert.Equal(t, expectedGraphQLRequest, &graphql.Request{
			Query: "query { hello }",
		})
	})

	t.Run("should return no error and success if no error occurs and OTel with detailedTracing is enabled", func(t *testing.T) {
		var expectedGraphQLRequest *graphql.Request
		engine, mocks := newTestEngineV2(t, withOpenTelemetryTestEngineV2(true))
		defer mocks.controller.Finish()
		engine.ctxStoreRequestFunc = func(r *http.Request, gqlRequest *graphql.Request) {
			expectedGraphQLRequest = gqlRequest
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := &httptest.ResponseRecorder{}

		expectedContext, _ := engine.OpenTelemetry.TracerProvider.Tracer().Start(request.Context(), "tracer test validation")
		mocks.requestProcessor.EXPECT().ProcessRequest(gomock.Eq(expectedContext), gomock.Eq(recorder), gomock.Eq(request)).
			Return(nil, 200)

		err, statusCode := engine.ProcessAndStoreGraphQLRequest(recorder, request)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
		assert.Equal(t, expectedGraphQLRequest, &graphql.Request{
			Query: "query { hello }",
		})
	})
}

func TestEngineV2_ProcessGraphQLComplexity(t *testing.T) {
	t.Run("should return error and status code 500 if the underlying complexity checker returns an internal fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		accessDefinition := &ComplexityAccessDefinition{}
		mocks.complexityChecker.EXPECT().DepthLimitExceeded(gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(ComplexityFailReasonInternalError)

		err, statusCode := engine.ProcessGraphQLComplexity(request, accessDefinition)
		assert.Error(t, err)
		assert.Equal(t, 500, statusCode)
	})

	t.Run("should return error and status code 403 if the underlying complexity checker returns fail reason depth limit exceeded", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		accessDefinition := &ComplexityAccessDefinition{}
		mocks.complexityChecker.EXPECT().DepthLimitExceeded(gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(ComplexityFailReasonDepthLimitExceeded)

		err, statusCode := engine.ProcessGraphQLComplexity(request, accessDefinition)
		assert.Error(t, err)
		assert.Equal(t, 403, statusCode)
	})

	t.Run("should return no error and status code 200 if the underlying complexity checker returns no fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		accessDefinition := &ComplexityAccessDefinition{}
		mocks.complexityChecker.EXPECT().DepthLimitExceeded(gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(ComplexityFailReasonNone)

		err, statusCode := engine.ProcessGraphQLComplexity(request, accessDefinition)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
	})
}

func TestEngineV2_ProcessGraphQLGranularAccess(t *testing.T) {
	t.Run("should return error and status code 500 if the underlying granular access checker returns an internal fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		accessDefinition := &GranularAccessDefinition{}
		mocks.granularAccessChecker.EXPECT().CheckGraphQLRequestFieldAllowance(gomock.Eq(recorder), gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(GraphQLGranularAccessResult{
				FailReason: GranularAccessFailReasonInternalError,
			})

		err, statusCode := engine.ProcessGraphQLGranularAccess(recorder, request, accessDefinition)
		assert.Error(t, err)
		assert.Equal(t, 500, statusCode)
	})

	t.Run("should return error and status code 400 if the underlying granular access checker returns a validation fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		accessDefinition := &GranularAccessDefinition{}
		mocks.granularAccessChecker.EXPECT().CheckGraphQLRequestFieldAllowance(gomock.Eq(recorder), gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(GraphQLGranularAccessResult{
				FailReason:      GranularAccessFailReasonValidationError,
				ValidationError: errors.New("failed validation"),
			})

		err, statusCode := engine.ProcessGraphQLGranularAccess(recorder, request, accessDefinition)
		assert.Error(t, err)
		assert.Equal(t, 400, statusCode)
	})

	t.Run("should return no error and status code 200 if the underlying granular access checker returns no fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { hello }"}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		accessDefinition := &GranularAccessDefinition{}
		mocks.granularAccessChecker.EXPECT().CheckGraphQLRequestFieldAllowance(gomock.Eq(recorder), gomock.Eq(request), gomock.Eq(accessDefinition)).
			Return(GraphQLGranularAccessResult{
				FailReason: GranularAccessFailReasonNone,
			})

		err, statusCode := engine.ProcessGraphQLGranularAccess(recorder, request, accessDefinition)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
	})
}

func TestEngineV2_HandleReverseProxy(t *testing.T) {
	t.Run("should return error if reverse proxy pre handler returns error", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest: &http.Request{},
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypeNone, errors.New("error"))

		_, hijacked, err := engine.HandleReverseProxy(params)
		assert.Error(t, err)
		assert.False(t, hijacked)
	})

	t.Run("should return error if execution engine is nil", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest: &http.Request{},
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypeGraphEngine, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{} // return empty request to avoid nil pointer dereference. We don't care about the request in this test
		}

		engine.ExecutionEngine = nil

		_, hijacked, err := engine.HandleReverseProxy(params)
		assert.Error(t, err)
		assert.False(t, hijacked)
	})

	t.Run("should execute graphql introspection if reverse proxy pre handler returns reverse proxy type introspection", func(t *testing.T) {
		engine, mocks := newTestEngineV2(t)
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest: &http.Request{},
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypeIntrospection, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{} // return empty request to avoid nil pointer dereference. We don't care about the request in this test
		}

		result, hijacked, err := engine.HandleReverseProxy(params)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(result.Body)

		assert.NoError(t, err)
		assert.False(t, hijacked)
		assert.Equal(t, 200, result.StatusCode)
		assert.Equal(t, testIntrospectionResultEngineV1, body.String())
	})

	t.Run("should handover request to graphql execution engine if reverse proxy pre handler returns reverse proxy type graph engine", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"hello": "world"}`))
		}))
		t.Cleanup(server.Close)

		engine, mocks := newTestEngineV2(t, withApiDefinitionTestEngineV2(newTestApiDefinitionV2(apidef.GraphQLExecutionModeExecutionEngine, server.URL)))
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest: &http.Request{},
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypeGraphEngine, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{
				Query: "query { hello }",
			}
		}

		result, hijacked, err := engine.HandleReverseProxy(params)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(result.Body)

		assert.NoError(t, err)
		assert.False(t, hijacked)
		assert.Equal(t, 200, result.StatusCode)
		assert.Equal(t, `{"data":{"hello":"world"}}`, body.String())
	})

	t.Run("should return error if reverse proxy pre handler returns proxy type preflight and execution mode is NOT proxy only", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		t.Cleanup(server.Close)

		engine, mocks := newTestEngineV2(t, withApiDefinitionTestEngineV2(newTestApiDefinitionV2(apidef.GraphQLExecutionModeSubgraph, server.URL)))

		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest:      &http.Request{},
			IsCORSPreflight: true,
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypePreFlight, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{}
		}

		result, hijacked, err := engine.HandleReverseProxy(params)
		var body bytes.Buffer
		if result != nil {
			_, _ = body.ReadFrom(result.Body)
		}

		assert.Error(t, err)
		assert.False(t, hijacked)
		assert.Nil(t, result)
	})

	t.Run("should return successful if reverse proxy pre handler returns proxy type preflight and execution mode is proxy only", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		t.Cleanup(server.Close)

		engine, mocks := newTestEngineV2(t, withApiDefinitionTestEngineV2(newTestApiDefinitionV2(apidef.GraphQLExecutionModeProxyOnly, server.URL)))
		defer mocks.controller.Finish()
		params := ReverseProxyParams{
			OutRequest:      &http.Request{},
			IsCORSPreflight: true,
		}
		mocks.reverseProxyPreHandler.EXPECT().PreHandle(gomock.Eq(params)).
			Return(ReverseProxyTypePreFlight, nil)

		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphql.Request {
			return &graphql.Request{}
		}

		result, hijacked, err := engine.HandleReverseProxy(params)
		var body bytes.Buffer
		if result != nil {
			_, _ = body.ReadFrom(result.Body)
		}

		assert.NoError(t, err)
		assert.False(t, hijacked)
		assert.Nil(t, result)
	})
}

type testEngineV2Options struct {
	targetURL     string
	apiDefinition *apidef.APIDefinition
	otelConfig    EngineV2OTelConfig
}

type testEngineV2Option func(*testEngineV2Options)

func withApiDefinitionTestEngineV2(apiDefinition *apidef.APIDefinition) testEngineV2Option {
	return func(options *testEngineV2Options) {
		options.apiDefinition = apiDefinition
	}
}

func withOpenTelemetryTestEngineV2(detailedTracing bool) testEngineV2Option {
	return func(options *testEngineV2Options) {
		options.apiDefinition.DetailedTracing = detailedTracing
		logrusLogger := logrus.New()
		logrusLogger.SetOutput(io.Discard)

		traceProvider := otel.InitOpenTelemetry(
			context.Background(),
			logrusLogger,
			&otel.OpenTelemetry{},
			"test",
			"test",
			false,
			"test",
			false,
			[]string{},
		)

		options.otelConfig = EngineV2OTelConfig{
			Enabled:        true,
			Config:         otel.OpenTelemetry{},
			TracerProvider: traceProvider,
		}
	}
}

func newTestEngineV2(t *testing.T, options ...testEngineV2Option) (*EngineV2, engineV2Mocks) {
	t.Helper()

	definedOptions := testEngineV2Options{
		otelConfig:    EngineV2OTelConfig{},
		apiDefinition: newTestApiDefinitionV2(apidef.GraphQLExecutionModeProxyOnly, "http://example.com"),
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
		Logger:          logrusLogger,
		ApiDefinition:   definedOptions.apiDefinition,
		HttpClient:      &http.Client{},
		StreamingClient: &http.Client{},
		OpenTelemetry:   definedOptions.otelConfig,
		Injections:      EngineV2Injections{},
	})
	require.NoError(t, err)

	// Set mocks
	engineV2.graphqlRequestProcessor = mocks.requestProcessor
	engineV2.complexityChecker = mocks.complexityChecker
	engineV2.granularAccessChecker = mocks.granularAccessChecker
	engineV2.reverseProxyPreHandler = mocks.reverseProxyPreHandler

	return engineV2, mocks
}

func newTestApiDefinitionV2(executionMode apidef.GraphQLExecutionMode, targetUrl string) *apidef.APIDefinition {
	return &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Enabled:       true,
			ExecutionMode: executionMode,
			Version:       apidef.GraphQLConfigVersion2,
			Schema:        testSchemaEngineV2,
			Engine: apidef.GraphQLEngineConfig{
				FieldConfigs: nil,
				DataSources: []apidef.GraphQLEngineDataSource{
					{
						Kind:     apidef.GraphQLEngineDataSourceKindREST,
						Name:     "Default",
						Internal: false,
						RootFields: []apidef.GraphQLTypeFields{
							{
								Type:   "Query",
								Fields: []string{"hello", "helloName"},
							},
						},
						Config: []byte(`{
							"url": "` + targetUrl + `",
							"method": "POST"
						}`),
					},
				},
				GlobalHeaders: nil,
			},
		},
	}
}

var testSchemaEngineV2 = `
type Query {
	hello: String
	helloName(name: String!): String
}
`
