package graphengine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jensneuse/abstractlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
)

func NewTestEngine(t *testing.T) *EngineV3 {
	t.Helper()

	gqlTools := graphqlGoToolsV2{}
	parsedSchema, err := gqlTools.parseSchema(testSchemaEngineV1)
	require.NoError(t, err)

	return &EngineV3{
		schema:                 parsedSchema,
		logger:                 abstractlogger.Noop{},
		ctxRetrieveRequestFunc: nil,
	}
}

func TestEngineV3_ProcessRequest(t *testing.T) {
	t.Run("should return error and 500 when request is nil", func(t *testing.T) {
		engine := NewTestEngine(t)
		err, statusCode := engine.ProcessRequest(context.Background(), nil, nil)

		assert.Error(t, err)
		assert.Equal(t, 500, statusCode)
	})

	t.Run("should return error and 400 when validation fails", func(t *testing.T) {
		engine := NewTestEngine(t)
		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphqlv2.Request {
			return &graphqlv2.Request{
				Query: "query { goodBye }",
			}
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query { goodBye }"}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		err, statusCode := engine.ProcessRequest(context.Background(), recorder, request)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(recorder.Body)

		assert.Error(t, err)
		assert.Equal(t, 400, statusCode)
		assert.Equal(t, `{"errors":[{"message":"field: goodBye not defined on type: Query","path":["query","goodBye"]}],"data":null}`, body.String())
	})

	t.Run("should return error and 400 when input validation fails", func(t *testing.T) {
		engine := NewTestEngine(t)
		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphqlv2.Request {
			return &graphqlv2.Request{
				Query:     "query($name: String!) { helloName(name: $name) }",
				Variables: json.RawMessage(`{"name": 123}`),
			}
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query($name: String!) { helloName(name: $name) }","variables": {"name": 123}}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		err, statusCode := engine.ProcessRequest(context.Background(), recorder, request)
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(recorder.Body)

		assert.Error(t, err)
		assert.Equal(t, 400, statusCode)
		assert.Equal(t, `{"errors":[{"message":"Variable \"$name\" got invalid value 123; String cannot represent a non string value: 123"}],"data":null}`, body.String())
	})

	t.Run("should return no error and 200 when everything passes", func(t *testing.T) {
		engine := NewTestEngine(t)
		engine.ctxRetrieveRequestFunc = func(r *http.Request) *graphqlv2.Request {
			return &graphqlv2.Request{
				Query:     "query($name: String!) { helloName(name: $name) }",
				Variables: json.RawMessage(`{"name": "James T. Kirk"}`),
			}
		}

		request, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer([]byte(`{"query": "query($name: String!) { helloName(name: $name) }","variables": {"name": 123}}`)))
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		err, statusCode := engine.ProcessRequest(context.Background(), recorder, request)
		assert.NoError(t, err)
		assert.Equal(t, 200, statusCode)
	})
}
