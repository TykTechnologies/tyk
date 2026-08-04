package graphengine

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jensneuse/abstractlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
)

func TestReverseProxyPreHandlerV2_PreHandle(t *testing.T) {
	t.Run("should return error on CORS preflight request", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodOptions,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			if r == request {
				return &graphqlv2.Request{
					Query: operation,
				}
			}

			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:      request,
			NeedsEngine:     true,
			IsCORSPreflight: true,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypePreFlight, result)
	})

	t.Run("should return ReverseProxyTypeWebsocketUpgrade on websocket upgrade", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			return nil // an upgrade request won't contain a graphql operation
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:         request,
			NeedsEngine:        true,
			IsWebSocketUpgrade: true,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypeWebsocketUpgrade, result)
	})

	t.Run("should return ReverseProxyTypeIntrospection on introspection request", func(t *testing.T) {
		operation := testIntrospectionQuery

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			if r == request {
				return &graphqlv2.Request{
					Query: operation,
				}
			}

			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest: request,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypeIntrospection, result)
	})

	t.Run("should return ReverseProxyTypeGraphEngine if engine is needed", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			if r == request {
				return &graphqlv2.Request{
					Query: operation,
				}
			}

			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:  request,
			NeedsEngine: true,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypeGraphEngine, result)
	})

	t.Run("should return ReverseProxyTypeNone if no engine is needed", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			if r == request {
				return &graphqlv2.Request{
					Query: operation,
				}
			}

			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:  request,
			NeedsEngine: false,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypeNone, result)
	})

}

func newTestReverseProxyPreHandlerV2(t *testing.T) *reverseProxyPreHandlerV2 {
	return &reverseProxyPreHandlerV2{
		apiDefinition: &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Enabled:       true,
				ExecutionMode: apidef.GraphQLExecutionModeProxyOnly,
			},
		},
		httpClient: &http.Client{},
		newReusableBodyReadCloser: func(closer io.ReadCloser) (io.ReadCloser, error) {
			return closer, nil
		},
	}
}

func TestGranularAccessCheckerV2_CheckGraphQLRequestFieldAllowance(t *testing.T) {
	t.Run("input object types", func(t *testing.T) {
		schemaStr := `
			input UserInput {
				name: String
				email: String
			}
			type Mutation {
				createUser(input: UserInput!): String
			}
			type Query {
				hello: String
			}
		`
		gqlTools := graphqlGoToolsV2{}
		parsedSchema, err := gqlTools.parseSchema(schemaStr)
		require.NoError(t, err)

		t.Run("should block restricted input object field (inline)", func(t *testing.T) {
			operation := `mutation { createUser(input: {name: "John", email: "john@example.com"}) }`
			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(fmt.Sprintf(`{"query": %q}`, operation))),
			)
			require.NoError(t, err)

			granularAccessChecker := &granularAccessCheckerV2{
				logger: abstractlogger.NoopLogger,
				schema: parsedSchema,
				ctxRetrieveGraphQLRequest: func(r *http.Request) *graphqlv2.Request {
					return &graphqlv2.Request{
						Query: operation,
					}
				},
			}

			result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
				RestrictedTypes: []GranularAccessType{
					{
						Name:   "UserInput",
						Fields: []string{"email"},
					},
				},
			})
			assert.Equal(t, GranularAccessFailReasonValidationError, result.FailReason)
			assert.Contains(t, result.ValidationError.Error(), "field: email is restricted on type: UserInput")
		})

		t.Run("should block restricted input object field (variable)", func(t *testing.T) {
			operation := `mutation ($in: UserInput!) { createUser(input: $in) }`
			variables := `{"in": {"name": "John", "email": "john@example.com"}}`
			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(fmt.Sprintf(`{"query": %q, "variables": %s}`, operation, variables))),
			)
			require.NoError(t, err)

			granularAccessChecker := &granularAccessCheckerV2{
				logger: abstractlogger.NoopLogger,
				schema: parsedSchema,
				ctxRetrieveGraphQLRequest: func(r *http.Request) *graphqlv2.Request {
					return &graphqlv2.Request{
						Query:     operation,
						Variables: []byte(variables),
					}
				},
			}

			result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
				RestrictedTypes: []GranularAccessType{
					{
						Name:   "UserInput",
						Fields: []string{"email"},
					},
				},
			})
			assert.Equal(t, GranularAccessFailReasonValidationError, result.FailReason)
			assert.Contains(t, result.ValidationError.Error(), "field: email is restricted on type: UserInput")
		})
	})
}
