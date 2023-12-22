package graphengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalgraphql "github.com/TykTechnologies/tyk/internal/graphql"
	"github.com/TykTechnologies/tyk/internal/otel"
)

func TestGraphqlRequestProcessorV1_ProcessRequest(t *testing.T) {
	t.Run("should return error and 500 when request is nil", func(t *testing.T) {
		processor := newTestGraphqlRequestProcessorV1(t)
		err, statusCode := processor.ProcessRequest(context.Background(), nil, nil)

		assert.Error(t, err)
		assert.Equal(t, 500, statusCode)
	})

	t.Run("should return error and 400 when validation fails", func(t *testing.T) {
		processor := newTestGraphqlRequestProcessorV1(t)
		processor.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
			return &graphql.Request{
				Query: "query { goodBye }",
			}
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { goodBye }"}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		err, statusCode := processor.ProcessRequest(context.Background(), recorder, request)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(recorder.Body)

		assert.Error(t, err)
		assert.Equal(t, 400, statusCode)
		assert.Equal(t, `{"errors":[{"message":"field: goodBye not defined on type: Query","path":["query","goodBye"]}]}`, body.String())
	})

	t.Run("should return error and 400 when input validation fails", func(t *testing.T) {
		processor := newTestGraphqlRequestProcessorV1(t)
		processor.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
			return &graphql.Request{
				Query:     "query($name: String!) { helloName(name: $name) }",
				Variables: json.RawMessage(`{"name": 123}`),
			}
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query($name: String!) { helloName(name: $name) }","variables": {"name": 123}}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		err, statusCode := processor.ProcessRequest(context.Background(), recorder, request)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(recorder.Body)

		assert.Error(t, err)
		assert.Equal(t, 400, statusCode)
		assert.Equal(t, `{"errors":[{"message":"Validation for variable \"name\" failed: expected string, but got number","locations":[{"line":1,"column":7}],"path":["query"]}]}`, body.String())
	})

	t.Run("should return no error and 200 when everything passes", func(t *testing.T) {
		processor := newTestGraphqlRequestProcessorV1(t)
		processor.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
			return &graphql.Request{
				Query:     "query($name: String!) { helloName(name: $name) }",
				Variables: json.RawMessage(`{"name": "James T. Kirk"}`),
			}
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query($name: String!) { helloName(name: $name) }","variables": {"name": 123}}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		err, statusCode := processor.ProcessRequest(context.Background(), recorder, request)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
	})
}

func TestGraphqlRequestProcessorWithOtelV1_ProcessRequest(t *testing.T) {
	t.Run("should return error and 500 when request is nil", func(t *testing.T) {
		processor := newTestGraphqlRequestProcessorWithOtelV1(t)
		err, statusCode := processor.ProcessRequest(context.Background(), nil, nil)

		assert.Error(t, err)
		assert.Equal(t, 500, statusCode)
	})

	t.Run("should return error and 400 when validation fails", func(t *testing.T) {
		processor := newTestGraphqlRequestProcessorWithOtelV1(t)
		processor.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
			return &graphql.Request{
				Query: "query { goodBye }",
			}
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { goodBye }"}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		err, statusCode := processor.ProcessRequest(context.Background(), recorder, request)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(recorder.Body)

		assert.Error(t, err)
		assert.Equal(t, 400, statusCode)
		assert.Equal(t, `{"errors":[{"message":"field: goodBye not defined on type: Query","path":["query","goodBye"]}]}`, body.String())
	})

	t.Run("should return error and 400 when input validation fails", func(t *testing.T) {
		processor := newTestGraphqlRequestProcessorWithOtelV1(t)
		processor.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
			return &graphql.Request{
				Query:     "query($name: String!) { helloName(name: $name) }",
				Variables: json.RawMessage(`{"name": 123}`),
			}
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query($name: String!) { helloName(name: $name) }","variables": {"name": 123}}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		err, statusCode := processor.ProcessRequest(context.Background(), recorder, request)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(recorder.Body)

		assert.Error(t, err)
		assert.Equal(t, 400, statusCode)
		assert.Equal(t, `{"errors":[{"message":"Validation for variable \"name\" failed: expected string, but got number","locations":[{"line":1,"column":7}],"path":["query"]}]}`, body.String())
	})

	t.Run("should return no error and 200 when everything passes", func(t *testing.T) {
		processor := newTestGraphqlRequestProcessorWithOtelV1(t)
		processor.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
			return &graphql.Request{
				Query:     "query($name: String!) { helloName(name: $name) }",
				Variables: json.RawMessage(`{"name": "James T. Kirk"}`),
			}
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query($name: String!) { helloName(name: $name) }","variables": {"name": 123}}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		err, statusCode := processor.ProcessRequest(context.Background(), recorder, request)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
	})
}

func newTestGraphqlRequestProcessorV1(t *testing.T) *graphqlRequestProcessorV1 {
	gqlTools := graphqlGoToolsV1{}
	parsedSchema, err := gqlTools.parseSchema(testSchemaEngineV1)
	require.NoError(t, err)

	return &graphqlRequestProcessorV1{
		logger:             abstractlogger.NoopLogger,
		schema:             parsedSchema,
		ctxRetrieveRequest: nil,
	}
}

func newTestGraphqlRequestProcessorWithOtelV1(t *testing.T) *graphqlRequestProcessorWithOtelV1 {
	gqlTools := graphqlGoToolsV1{}
	parsedSchema, err := gqlTools.parseSchema(testSchemaEngineV1)
	require.NoError(t, err)

	logrusLogger := logrus.New()
	logrusLogger.SetOutput(io.Discard)

	traceProvider := otel.InitOpenTelemetry(context.Background(), logrusLogger, &otel.OpenTelemetry{}, "test", "test", false, "test", false, []string{})

	executionEngineV2, err := graphql.NewExecutionEngineV2(context.Background(), abstractlogger.NoopLogger, graphql.NewEngineV2Configuration(parsedSchema))
	otelExecutor, err := internalgraphql.NewOtelGraphqlEngineV2Basic(traceProvider, executionEngineV2)
	require.NoError(t, err)

	return &graphqlRequestProcessorWithOtelV1{
		logger:             abstractlogger.NoopLogger,
		schema:             parsedSchema,
		ctxRetrieveRequest: nil,
		otelExecutor:       otelExecutor,
	}
}
