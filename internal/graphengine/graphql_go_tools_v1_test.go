package graphengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func TestComplexityCheckerV1_DepthLimitExceeded(t *testing.T) {
	t.Run("should return ComplexityFailReasonNone if it is an introspection query", func(t *testing.T) {
		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, testIntrospectionQuery),
			)))
		require.NoError(t, err)

		complexityChecker := newTestComplexityCheckerV1(t)
		complexityChecker.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
			if r == request {
				return &graphql.Request{
					Query: testIntrospectionQuery,
				}
			}

			return nil
		}

		result := complexityChecker.DepthLimitExceeded(request, nil)
		assert.Equal(t, ComplexityFailReasonNone, result)
	})

	t.Run("global query depth limit", func(t *testing.T) {
		t.Run("should return ComplexityFailReasonDepthLimitExceeded if global depth limit is exceeded", func(t *testing.T) {
			operation := `{ countries { continent { countries { continent } } } }` // depth 4

			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(
					fmt.Sprintf(`{"query": "%s"}`, operation),
				)))
			require.NoError(t, err)

			complexityChecker := newTestComplexityCheckerV1(t, withTestComplexityCheckerV1Schema(testSchemaNestedEngineV1))
			complexityChecker.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
				if r == request {
					return &graphql.Request{
						Query: operation,
					}
				}

				return nil
			}

			result := complexityChecker.DepthLimitExceeded(request, &ComplexityAccessDefinition{
				Limit: ComplexityLimit{
					MaxQueryDepth: 3,
				},
			})
			assert.Equal(t, ComplexityFailReasonDepthLimitExceeded, result)
		})

		t.Run("should return ComplexityFailReasonNone if global depth limit is not exceeded", func(t *testing.T) {
			operation := `{ countries { continent } }` // depth 2

			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(
					fmt.Sprintf(`{"query": "%s"}`, operation),
				)))
			require.NoError(t, err)

			complexityChecker := newTestComplexityCheckerV1(t, withTestComplexityCheckerV1Schema(testSchemaNestedEngineV1))
			complexityChecker.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
				if r == request {
					return &graphql.Request{
						Query: operation,
					}
				}

				return nil
			}

			result := complexityChecker.DepthLimitExceeded(request, &ComplexityAccessDefinition{
				Limit: ComplexityLimit{
					MaxQueryDepth: 3,
				},
			})
			assert.Equal(t, ComplexityFailReasonNone, result)
		})
	})

	t.Run("per query depth limit", func(t *testing.T) {
		t.Run("should return ComplexityFailReasonDepthLimitExceeded if per query depth limit is exceeded", func(t *testing.T) {
			operation := `{ countries { continent { countries { continent { countries } } } } }` // depth 5

			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(
					fmt.Sprintf(`{"query": "%s"}`, operation),
				)))
			require.NoError(t, err)

			complexityChecker := newTestComplexityCheckerV1(t, withTestComplexityCheckerV1Schema(testSchemaNestedEngineV1))
			complexityChecker.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
				if r == request {
					return &graphql.Request{
						Query: operation,
					}
				}

				return nil
			}

			result := complexityChecker.DepthLimitExceeded(request, &ComplexityAccessDefinition{
				FieldAccessRights: []ComplexityFieldAccessDefinition{
					{
						TypeName:  "Query",
						FieldName: "countries",
						Limits: ComplexityFieldLimits{
							MaxQueryDepth: 3,
						},
					},
				},
			})
			assert.Equal(t, ComplexityFailReasonDepthLimitExceeded, result)
		})

		t.Run("should return ComplexityFailReasonNone if global depth limit is not exceeded", func(t *testing.T) {
			operation := `{ countries { continent } }` // depth 2

			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(
					fmt.Sprintf(`{"query": "%s"}`, operation),
				)))
			require.NoError(t, err)

			complexityChecker := newTestComplexityCheckerV1(t, withTestComplexityCheckerV1Schema(testSchemaNestedEngineV1))
			complexityChecker.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
				if r == request {
					return &graphql.Request{
						Query: operation,
					}
				}

				return nil
			}

			result := complexityChecker.DepthLimitExceeded(request, &ComplexityAccessDefinition{
				FieldAccessRights: []ComplexityFieldAccessDefinition{
					{
						TypeName:  "Query",
						FieldName: "countries",
						Limits: ComplexityFieldLimits{
							MaxQueryDepth: 3,
						},
					},
				},
			})
			assert.Equal(t, ComplexityFailReasonNone, result)
		})

		t.Run("should fallback to global depth limit and return ComplexityFailReasonDepthLimitExceeded if it exceeds it", func(t *testing.T) {
			operation := `{ countries { continent { countries { continent { countries } } } } }` // depth 5

			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(
					fmt.Sprintf(`{"query": "%s"}`, operation),
				)))
			require.NoError(t, err)

			complexityChecker := newTestComplexityCheckerV1(t, withTestComplexityCheckerV1Schema(testSchemaNestedEngineV1))
			complexityChecker.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
				if r == request {
					return &graphql.Request{
						Query: operation,
					}
				}

				return nil
			}

			result := complexityChecker.DepthLimitExceeded(request, &ComplexityAccessDefinition{
				Limit: ComplexityLimit{MaxQueryDepth: 4},
				FieldAccessRights: []ComplexityFieldAccessDefinition{
					{
						TypeName:  "Query",
						FieldName: "continents",
						Limits: ComplexityFieldLimits{
							MaxQueryDepth: 6,
						},
					},
				},
			})
			assert.Equal(t, ComplexityFailReasonDepthLimitExceeded, result)
		})
	})

}

func TestComplexityCheckerV1_DepthLimitEnabled(t *testing.T) {
	t.Run("should return false if access definition is nil", func(t *testing.T) {
		complexityChecker := newTestComplexityCheckerV1(t)
		result := complexityChecker.depthLimitEnabled(nil)
		assert.False(t, result)
	})

	t.Run("should return false if global depth limit is set to -1 and no field access rights do exist", func(t *testing.T) {
		complexityChecker := newTestComplexityCheckerV1(t)
		result := complexityChecker.depthLimitEnabled(&ComplexityAccessDefinition{
			Limit: ComplexityLimit{
				MaxQueryDepth: -1,
			},
			FieldAccessRights: nil,
		})
		assert.False(t, result)
	})

	t.Run("should return true if global depth limit is not set to -1 and no field access rights do exist", func(t *testing.T) {
		complexityChecker := newTestComplexityCheckerV1(t)
		result := complexityChecker.depthLimitEnabled(&ComplexityAccessDefinition{
			Limit: ComplexityLimit{
				MaxQueryDepth: 1,
			},
			FieldAccessRights: nil,
		})
		assert.True(t, result)
	})

	t.Run("should return true if global depth limit is set to -1 and field access rights do exist", func(t *testing.T) {
		complexityChecker := newTestComplexityCheckerV1(t)
		result := complexityChecker.depthLimitEnabled(&ComplexityAccessDefinition{
			Limit: ComplexityLimit{
				MaxQueryDepth: -1,
			},
			FieldAccessRights: []ComplexityFieldAccessDefinition{
				{
					TypeName:  "Query",
					FieldName: "continents",
					Limits: ComplexityFieldLimits{
						MaxQueryDepth: 1,
					},
				},
			},
		})
		assert.True(t, result)
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

type testComplexityCheckerV1Options struct {
	schema string
}

type testComplexityCheckerV1Option func(*testComplexityCheckerV1Options)

func withTestComplexityCheckerV1Schema(schema string) testComplexityCheckerV1Option {
	return func(opts *testComplexityCheckerV1Options) {
		opts.schema = schema
	}
}

func newTestComplexityCheckerV1(t *testing.T, options ...testComplexityCheckerV1Option) *complexityCheckerV1 {
	opts := &testComplexityCheckerV1Options{
		schema: testSchemaEngineV1,
	}

	for _, option := range options {
		option(opts)
	}

	gqlTools := graphqlGoToolsV1{}
	parsedSchema, err := gqlTools.parseSchema(opts.schema)
	require.NoError(t, err)

	return &complexityCheckerV1{
		logger:             abstractlogger.NoopLogger,
		schema:             parsedSchema,
		ctxRetrieveRequest: nil,
	}
}
