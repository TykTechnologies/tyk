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

	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
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
	t.Run("should return ComplexityFailReasonNone if no graphql request is stored in the context", func(t *testing.T) {
		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			nil,
		)
		require.NoError(t, err)

		complexityChecker := newTestComplexityCheckerV1(t)
		complexityChecker.ctxRetrieveRequest = func(r *http.Request) *graphql.Request {
			return nil // could be a websocket upgrade request, so no graphql operation stored in that case
		}

		result := complexityChecker.DepthLimitExceeded(request, &ComplexityAccessDefinition{})
		assert.Equal(t, ComplexityFailReasonNone, result)
	})

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

		result := complexityChecker.DepthLimitExceeded(request, &ComplexityAccessDefinition{})
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

		t.Run("should return ComplexityFailReasonNone if global depth limit is set to 0", func(t *testing.T) {
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
					MaxQueryDepth: 0,
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

func TestGranularAccessCheckerV1_CheckGraphQLRequestFieldAllowance(t *testing.T) {
	t.Run("should return GranularAccessFailReasonNone if no graphql request is stored in context", func(t *testing.T) {
		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			nil,
		)
		require.NoError(t, err)

		granularAccessChecker := newTestGranularAccessCheckerV1(t)
		granularAccessChecker.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			return nil // could be a websocket upgrade request, so no graphql operation stored in that case
		}

		result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
			RestrictedTypes: []GranularAccessType{
				{
					Name:   "Query",
					Fields: []string{"helloName"},
				},
			},
		})
		assert.Equal(t, GranularAccessFailReasonNone, result.FailReason)
	})

	t.Run("should return GranularAccessFailReasonNone if no lists are provided", func(t *testing.T) {
		operation := `{ helloName("eddy") }`

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		granularAccessChecker := newTestGranularAccessCheckerV1(t)
		granularAccessChecker.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			return nil
		}

		result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{})
		assert.Equal(t, GranularAccessFailReasonNone, result.FailReason)
	})

	t.Run("should return GranularAccessFailReasonIntrospectionDisabled if introspection check is disabled", func(t *testing.T) {
		operation := testIntrospectionQuery

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		granularAccessChecker := newTestGranularAccessCheckerV1(t)
		granularAccessChecker.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			if r == request {
				return &graphql.Request{
					Query: operation,
				}
			}
			return nil
		}

		result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
			DisableIntrospection: true,
		})
		assert.Equal(t, GranularAccessFailReasonIntrospectionDisabled, result.FailReason)
	})

	t.Run("should return GranularAccessFailReasonNone if DisableIntrospection is set to false and AllowedTypes is not empty", func(t *testing.T) {
		operation := testIntrospectionQuery

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		granularAccessChecker := newTestGranularAccessCheckerV1(t)
		granularAccessChecker.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			if r == request {
				return &graphql.Request{
					Query: operation,
				}
			}
			return nil
		}

		result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
			DisableIntrospection: false,
			AllowedTypes: []GranularAccessType{
				{
					Name:   "Query",
					Fields: []string{"hello"},
				},
			},
		})
		assert.Equal(t, GranularAccessFailReasonNone, result.FailReason)
	})

	t.Run("should return GranularAccessFailReasonNone if DisableIntrospection is set to false and RestrictedTypes is not empty", func(t *testing.T) {
		operation := testIntrospectionQuery

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		granularAccessChecker := newTestGranularAccessCheckerV1(t)
		granularAccessChecker.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			if r == request {
				return &graphql.Request{
					Query: operation,
				}
			}
			return nil
		}

		result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
			DisableIntrospection: false,
			RestrictedTypes: []GranularAccessType{
				{
					Name:   "Query",
					Fields: []string{"helloName"},
				},
			},
		})
		assert.Equal(t, GranularAccessFailReasonNone, result.FailReason)
	})

	t.Run("allowed list", func(t *testing.T) {
		t.Run("should return GranularAccessFailReasonNone if the field is listed in allowed list", func(t *testing.T) {
			operation := `{ hello }`

			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(
					fmt.Sprintf(`{"query": "%s"}`, operation),
				)))
			require.NoError(t, err)

			granularAccessChecker := newTestGranularAccessCheckerV1(t)
			granularAccessChecker.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
				if r == request {
					return &graphql.Request{
						Query: operation,
					}
				}

				return nil
			}

			result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
				AllowedTypes: []GranularAccessType{
					{
						Name:   "Query",
						Fields: []string{"hello"},
					},
				},
			})
			assert.Equal(t, GranularAccessFailReasonNone, result.FailReason)
		})

		t.Run("should return GranularAccessFailReasonValidationError if the field is not listed in allowed list", func(t *testing.T) {
			operation := `{ helloName(name: "eddy") }`

			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(
					fmt.Sprintf(`{"query": "%s"}`, operation),
				)))
			require.NoError(t, err)

			granularAccessChecker := newTestGranularAccessCheckerV1(t)
			granularAccessChecker.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
				if r == request {
					return &graphql.Request{
						Query: operation,
					}
				}

				return nil
			}

			result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
				AllowedTypes: []GranularAccessType{
					{
						Name:   "Query",
						Fields: []string{"hello"},
					},
				},
			})
			assert.Equal(t, GranularAccessFailReasonValidationError, result.FailReason)
		})
	})

	t.Run("restricted list", func(t *testing.T) {
		t.Run("should return GranularAccessFailReasonNone if the field is not listed in restricted list", func(t *testing.T) {
			operation := `{ hello }`

			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(
					fmt.Sprintf(`{"query": "%s"}`, operation),
				)))
			require.NoError(t, err)

			granularAccessChecker := newTestGranularAccessCheckerV1(t)
			granularAccessChecker.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
				if r == request {
					return &graphql.Request{
						Query: operation,
					}
				}

				return nil
			}

			result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
				RestrictedTypes: []GranularAccessType{
					{
						Name:   "Query",
						Fields: []string{"helloName"},
					},
				},
			})
			assert.Equal(t, GranularAccessFailReasonNone, result.FailReason)
		})

		t.Run("should return GranularAccessFailReasonValidationError if the field is listed in restricted list", func(t *testing.T) {
			operation := `{ helloName(name:  "eddy") }`

			request, err := http.NewRequest(
				http.MethodPost,
				"http://example.com",
				bytes.NewBuffer([]byte(
					fmt.Sprintf(`{"query": "%s"}`, operation),
				)))
			require.NoError(t, err)

			granularAccessChecker := newTestGranularAccessCheckerV1(t)
			granularAccessChecker.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
				if r == request {
					return &graphql.Request{
						Query: operation,
					}
				}

				return nil
			}

			result := granularAccessChecker.CheckGraphQLRequestFieldAllowance(httptest.NewRecorder(), request, &GranularAccessDefinition{
				RestrictedTypes: []GranularAccessType{
					{
						Name:   "Query",
						Fields: []string{"helloName"},
					},
				},
			})
			assert.Equal(t, GranularAccessFailReasonValidationError, result.FailReason)
		})
	})
}

func TestReverseProxyPreHandlerV1_PreHandle(t *testing.T) {
	t.Run("should return error on CORS preflight request", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodOptions,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV1(t, apidef.GraphQLExecutionModeSubgraph)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			if r == request {
				return &graphql.Request{
					Query: operation,
				}
			}

			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:      request,
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

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV1(t, apidef.GraphQLExecutionModeProxyOnly)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
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

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV1(t, apidef.GraphQLExecutionModeProxyOnly)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			if r == request {
				return &graphql.Request{
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

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV1(t, apidef.GraphQLExecutionModeProxyOnly)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			if r == request {
				return &graphql.Request{
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

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV1(t, apidef.GraphQLExecutionModeProxyOnly)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			if r == request {
				return &graphql.Request{
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

	t.Run("should return ReverseProxyTypePreFlight if CORS pre flight is true", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodOptions,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV1(t, apidef.GraphQLExecutionModeProxyOnly)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphql.Request {
			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:      request,
			IsCORSPreflight: true,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypePreFlight, result)
	})
}

func newTestGraphqlRequestProcessorV1(t *testing.T) *graphqlRequestProcessorV1 {
	t.Helper()

	gqlTools := graphqlGoToolsV1{}
	parsedSchema, err := gqlTools.parseSchema(testSchemaEngineV1)
	require.NoError(t, err)

	return &graphqlRequestProcessorV1{
		logger:             abstractlogger.NoopLogger,
		schema:             parsedSchema,
		ctxRetrieveRequest: nil,
	}
}

func newTestGraphqlRequestProcessorWithOtelV1(t *testing.T) *graphqlRequestProcessorWithOTelV1 {
	t.Helper()

	gqlTools := graphqlGoToolsV1{}
	parsedSchema, err := gqlTools.parseSchema(testSchemaEngineV1)
	require.NoError(t, err)

	logrusLogger := logrus.New()
	logrusLogger.SetOutput(io.Discard)

	traceProvider := otel.InitOpenTelemetry(context.Background(), logrusLogger, &otel.OpenTelemetry{}, "test", "test", false, "test", false, []string{})

	executionEngineV2, err := graphql.NewExecutionEngineV2(context.Background(), abstractlogger.NoopLogger, graphql.NewEngineV2Configuration(parsedSchema))
	otelExecutor, err := internalgraphql.NewOtelGraphqlEngineV2Basic(traceProvider, executionEngineV2)
	require.NoError(t, err)

	return &graphqlRequestProcessorWithOTelV1{
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
	t.Helper()

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

func newTestGranularAccessCheckerV1(t *testing.T) *granularAccessCheckerV1 {
	t.Helper()

	gqlTools := graphqlGoToolsV1{}
	parsedSchema, err := gqlTools.parseSchema(testSchemaEngineV1)
	require.NoError(t, err)

	return &granularAccessCheckerV1{
		logger:                    abstractlogger.NoopLogger,
		schema:                    parsedSchema,
		ctxRetrieveGraphQLRequest: nil,
	}
}

func newTestReverseProxyPreHandlerV1(_ *testing.T, executionMode apidef.GraphQLExecutionMode) *reverseProxyPreHandlerV1 {
	return &reverseProxyPreHandlerV1{
		apiDefinition: &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Enabled:       true,
				ExecutionMode: executionMode,
			},
		},
		httpClient: &http.Client{},
		newReusableBodyReadCloser: func(closer io.ReadCloser) (io.ReadCloser, error) {
			return closer, nil
		},
	}
}
