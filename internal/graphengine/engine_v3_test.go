package graphengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
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

func TestEngineV3_HandleReverseProxyIsolatesCallerAuthorization(t *testing.T) {
	apiDefinition := newUDGApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql")
	engine := newIsolationEngineV3(t, apiDefinition, "query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, upstream, "", token)
	}

	waitForUpstreamCalls(t, upstream.authorizationRecorder, 2)
	assert.ElementsMatch(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
}

func TestEngineV3_SSESubscriptionIsolatesCallerAuthorization(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingSSEUpstream(t, upstream)
	engine := newIsolationEngineV3(t,
		newUDGSubscriptionApiDefinition(t, apidef.GraphQLConfigVersion3Preview, apidef.GQLSubscriptionSSE, server.URL),
		"subscription { count }")

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, http.DefaultTransport, "", token)
	}

	waitForUpstreamCalls(t, upstream, 2)
	assert.ElementsMatch(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
}

func TestEngineV3_WebSocketSubscriptionIsolatesCallerAuthorization(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingWSUpstream(t, upstream, protocolGraphQLWS, messageTypeData)
	engine := newIsolationEngineV3(t,
		newUDGSubscriptionApiDefinition(t, apidef.GraphQLConfigVersion3Preview, apidef.GQLSubscriptionWS, server.URL),
		"subscription { count }")

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, http.DefaultTransport, "", token)
	}

	waitForUpstreamCalls(t, upstream, 2)
	assert.ElementsMatch(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
}

func TestNewEngineV3_ConfiguresHTTPClients(t *testing.T) {
	newEngine := func(t *testing.T, httpClient, streamingClient *http.Client) *EngineV3 {
		t.Helper()
		apiDefinition := newTestApiDefinitionV2(apidef.GraphQLExecutionModeExecutionEngine, "http://upstream.example/graphql")
		apiDefinition.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		schema, err := graphqlv2.NewSchemaFromString(apiDefinition.GraphQL.Schema)
		require.NoError(t, err)
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		engine, err := NewEngineV3(EngineV3Options{
			Logger:          logger,
			Schema:          schema,
			ApiDefinition:   apiDefinition,
			HttpClient:      httpClient,
			StreamingClient: streamingClient,
			Injections: EngineV3Injections{
				ContextRetrieveRequest: func(*http.Request) *graphqlv2.Request {
					return &graphqlv2.Request{Query: "query { hello }"}
				},
				NewReusableBodyReadCloser: testReusableReadCloser,
				TykVariableReplacer: func(_ *http.Request, value string, _ bool) string {
					return value
				},
			},
		})
		require.NoError(t, err)
		t.Cleanup(engine.Cancel)
		return engine
	}

	t.Run("should configure both the http client and the streaming client", func(t *testing.T) {
		httpClient := &http.Client{Transport: taggedRoundTripper("http")}
		streamingClient := &http.Client{Transport: taggedRoundTripper("streaming")}

		newEngine(t, httpClient, streamingClient)

		httpTransport, ok := httpClient.Transport.(*GraphQLEngineTransport)
		require.True(t, ok, "the http client transport should be wrapped")
		assert.Equal(t, taggedRoundTripper("http"), httpTransport.originalTransport)
		streamingTransport, ok := streamingClient.Transport.(*GraphQLEngineTransport)
		require.True(t, ok, "the streaming client transport should be wrapped")
		assert.Equal(t, taggedRoundTripper("streaming"), streamingTransport.originalTransport)
	})

	t.Run("should not fail when the streaming client is nil", func(t *testing.T) {
		// The gateway does not set a streaming client for version 3-preview,
		// see gateway/mw_graphql.go.
		httpClient := &http.Client{Transport: taggedRoundTripper("http")}

		assert.NotPanics(t, func() {
			newEngine(t, httpClient, nil)
		})

		_, ok := httpClient.Transport.(*GraphQLEngineTransport)
		assert.True(t, ok, "the http client transport should be wrapped")
	})
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
