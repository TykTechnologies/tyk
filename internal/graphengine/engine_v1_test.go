package graphengine

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/golang/mock/gomock"
	"github.com/jensneuse/abstractlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type engineV1Mocks struct {
	controller        *gomock.Controller
	requestProcessor  *MockGraphQLRequestProcessor
	complexityChecker *MockComplexityChecker
}

func TestEngineV1_HasSchema(t *testing.T) {
	t.Run("should be true if engine has a schema", func(t *testing.T) {
		engine := EngineV1{
			Schema: &graphql.Schema{},
		}
		assert.True(t, engine.HasSchema())
	})
	t.Run("should be false if engine has no schema", func(t *testing.T) {
		engine := EngineV1{
			Schema: nil,
		}
		assert.False(t, engine.HasSchema())
	})
}

func TestEngineV1_ProcessAndStoreGraphQLRequest(t *testing.T) {
	t.Run("should return error and Bad Request if it can't parse the gql request", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
		defer mocks.controller.Finish()
		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte("invalid gql request")))
		require.NoError(t, err)

		err, statusCode := engine.ProcessAndStoreGraphQLRequest(nil, request)
		assert.Equal(t, 400, statusCode)
		assert.Error(t, err)
	})

	t.Run("should return no error and success if no error occurs", func(t *testing.T) {
		var expectedGraphQLRequest *graphql.Request
		engine, mocks := newTestEngineV1(t)
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
}

func TestEngineV1_ProcessGraphQLComplexity(t *testing.T) {
	t.Run("should return error and status code 500 if the underlying complexity checker returns an internal fail reason", func(t *testing.T) {
		engine, mocks := newTestEngineV1(t)
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
		engine, mocks := newTestEngineV1(t)
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
		engine, mocks := newTestEngineV1(t)
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

func newTestEngineV1(t *testing.T) (*EngineV1, engineV1Mocks) {
	ctrl := gomock.NewController(t)
	mocks := engineV1Mocks{
		controller:        ctrl,
		requestProcessor:  NewMockGraphQLRequestProcessor(ctrl),
		complexityChecker: NewMockComplexityChecker(ctrl),
	}

	engine := &EngineV1{
		logger:                  abstractlogger.NoopLogger,
		graphqlRequestProcessor: mocks.requestProcessor,
		complexityChecker:       mocks.complexityChecker,
	}

	return engine, mocks
}
