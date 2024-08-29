package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/tyk/config"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	gqlwebsocket "github.com/TykTechnologies/graphql-go-tools/pkg/subscription/websocket"

	"github.com/TykTechnologies/tyk/test"
)

// Note: here we test only validation behaviour and do not expect real graphql responses here
func TestGraphQLMiddleware_RequestValidation(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
	})[0]

	t.Run("Bad schema", func(t *testing.T) {
		spec.GraphQL.Schema = "query: Query"
		g.Gw.LoadAPI(spec)

		_, _ = g.Run(t, test.TestCase{BodyMatch: "there was a problem proxying the request", Code: http.StatusInternalServerError})
	})

	t.Run("Introspection query with custom query type should successfully work", func(t *testing.T) {
		spec.GraphQL.Schema = "schema { query: query_root } type query_root { hello: word } type word { numOfLetters: Int }"
		spec.GraphQL.Version = apidef.GraphQLConfigVersion2
		g.Gw.LoadAPI(spec)

		request := gql.Request{
			OperationName: "IntrospectionQuery",
			Variables:     nil,
			Query:         gqlIntrospectionQuery,
		}

		_, _ = g.Run(t, test.TestCase{Data: request, BodyMatch: "__schema", Code: http.StatusOK})
	})

	t.Run("Empty request shouldn't be unmarshalled", func(t *testing.T) {
		spec.GraphQL.Schema = "schema { query: Query } type Query { hello: word } type word { numOfLetters: Int }"
		g.Gw.LoadAPI(spec)

		emptyRequest := ``

		_, _ = g.Run(t, test.TestCase{Data: emptyRequest, BodyMatch: gql.ErrEmptyRequest.Error(), Code: http.StatusBadRequest})
	})

	t.Run("Invalid query should fail", func(t *testing.T) {
		request := gql.Request{
			OperationName: "Goodbye",
			Variables:     nil,
			Query:         "query Goodbye { goodbye }",
		}

		_, _ = g.Run(t, test.TestCase{Data: request, Code: http.StatusBadRequest})
	})

	t.Run("Introspection query should successfully work", func(t *testing.T) {
		request := gql.Request{
			OperationName: "IntrospectionQuery",
			Variables:     nil,
			Query:         gqlIntrospectionQuery,
		}

		_, _ = g.Run(t, test.TestCase{Data: request, BodyMatch: "__schema", Code: http.StatusOK})
	})

	t.Run("with policies", func(t *testing.T) {
		spec.UseKeylessAccess = false

		spec.GraphQL.Schema = "schema { query: Query } type Query { hello: word } type word { numOfLetters: Int }"
		g.Gw.LoadAPI(spec)

		pID := g.CreatePolicy(func(p *user.Policy) {
			p.MaxQueryDepth = 1
			p.AccessRights = map[string]user.AccessDefinition{
				spec.APIID: {
					APIID:   spec.APIID,
					APIName: spec.Name,
				},
			}
		})

		policyAppliedSession, policyAppliedKey := g.CreateSession(func(s *user.SessionState) {
			s.ApplyPolicies = []string{pID}
		})

		directSession, directKey := g.CreateSession(func(s *user.SessionState) {
			s.MaxQueryDepth = 1
			s.AccessRights = map[string]user.AccessDefinition{
				spec.APIID: {
					APIID:   spec.APIID,
					APIName: spec.Name,
				},
			}
		})

		authHeaderWithDirectKey := map[string]string{
			header.Authorization: directKey,
		}

		authHeaderWithPolicyAppliedKey := map[string]string{
			header.Authorization: policyAppliedKey,
		}

		request := gql.Request{
			OperationName: "Hello",
			Variables:     nil,
			Query:         "query Hello { hello { numOfLetters } }",
		}

		t.Run("Depth limit exceeded", func(t *testing.T) {
			if directSession.MaxQueryDepth != 1 || policyAppliedSession.MaxQueryDepth != 1 {
				t.Fatal("MaxQueryDepth couldn't be applied to key")
			}

			_, _ = g.Run(t, []test.TestCase{
				{Headers: authHeaderWithDirectKey, Data: request, BodyMatch: "depth limit exceeded", Code: http.StatusForbidden},
				{Headers: authHeaderWithPolicyAppliedKey, Data: request, BodyMatch: "depth limit exceeded", Code: http.StatusForbidden},
			}...)
		})

		t.Run("Unlimited query depth", func(t *testing.T) {
			t.Run("0", func(t *testing.T) {
				directSession.MaxQueryDepth = 0
				_ = g.Gw.GlobalSessionManager.UpdateSession(directKey, directSession, 0, false)

				_, _ = g.Run(t, test.TestCase{Headers: authHeaderWithDirectKey, Data: request, BodyMatch: "hello", Code: http.StatusOK})
			})

			t.Run("-1", func(t *testing.T) {
				directSession.MaxQueryDepth = -1
				_ = g.Gw.GlobalSessionManager.UpdateSession(directKey, directSession, 0, false)

				_, _ = g.Run(t, test.TestCase{Headers: authHeaderWithDirectKey, Data: request, BodyMatch: "hello", Code: http.StatusOK})
			})
		})

		t.Run("Valid query should successfully work", func(t *testing.T) {
			directSession.MaxQueryDepth = 2
			_ = g.Gw.GlobalSessionManager.UpdateSession(directKey, directSession, 0, false)

			_, _ = g.Run(t, test.TestCase{Headers: authHeaderWithDirectKey, Data: request, BodyMatch: "hello", Code: http.StatusOK})
		})

		t.Run("Invalid query should return 403 when auth is failing", func(t *testing.T) {
			request.Query = "query Hello {"
			authHeaderWithInvalidDirectKey := map[string]string{
				header.Authorization: "invalid key",
			}
			_, _ = g.Run(t, test.TestCase{Headers: authHeaderWithInvalidDirectKey, Data: request, BodyMatch: "", Code: http.StatusForbidden})
		})
	})

	t.Run("null input on non nullable variable should fail with 400", func(t *testing.T) {
		testSpec := BuildAPI(func(spec *APISpec) {
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
			spec.GraphQL.Schema = gqlCountriesSchema
			spec.GraphQL.Version = apidef.GraphQLConfigVersion2
			spec.Proxy.TargetURL = testGraphQLProxyUpstream
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
		})[0]

		g.Gw.LoadAPI(testSpec)

		_, err := g.Run(
			t,
			test.TestCase{
				Path:   "/",
				Method: http.MethodPost,
				Data: gql.Request{
					Query:     gqlContinentQueryVariable,
					Variables: []byte(`{"code":null}`),
				},
				Code: 400,
			},
			test.TestCase{
				Path:   "/",
				Method: http.MethodPost,
				Data: gql.Request{
					Query:     gqlStateQueryVariable,
					Variables: []byte(`{"filter":{"code":{"eq":"filterString"}}}`),
				},
				Code: 400,
				BodyMatchFunc: func(i []byte) bool {
					return strings.Contains(string(i), `Validation for variable \"filter\" failed`)
				},
			})
		assert.NoError(t, err)
	})

	t.Run("fail input validation with otel tracing active", func(t *testing.T) {
		local := StartTest(func(globalConf *config.Config) {
			globalConf.OpenTelemetry.Enabled = true
		})
		defer local.Close()
		testSpec := BuildAPI(func(spec *APISpec) {
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
			spec.GraphQL.Schema = gqlCountriesSchema
			spec.GraphQL.Version = apidef.GraphQLConfigVersion2
			spec.Proxy.TargetURL = testGraphQLProxyUpstream
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
		})[0]

		local.Gw.LoadAPI(testSpec)

		_, err := local.Run(
			t,
			test.TestCase{
				Path:   "/",
				Method: http.MethodPost,
				Data: gql.Request{
					Query:     gqlContinentQueryVariable,
					Variables: []byte(`{"code":null}`),
				},
				Code: 400,
			},
			test.TestCase{
				Path:   "/",
				Method: http.MethodPost,
				Data: gql.Request{
					Query:     gqlStateQueryVariable,
					Variables: []byte(`{"filter":{"code":{"eq":"filterString"}}}`),
				},
				Code: 400,
				BodyMatchFunc: func(i []byte) bool {
					return strings.Contains(string(i), `Validation for variable \"filter\" failed`)
				},
			})
		assert.NoError(t, err)
	})

	t.Run("fail input validation if GQL engine is not v2, but OTel and detailed tracing is enabled", func(t *testing.T) {
		// See TT-11119, if OTel and detailed tracing is enabled but the GQL version is not 2 GW fails to serve the request
		// and panics.
		local := StartTest(func(globalConf *config.Config) {
			globalConf.OpenTelemetry.Enabled = true
		})
		defer local.Close()
		testSpec := BuildAPI(func(spec *APISpec) {
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
			spec.GraphQL.Schema = gqlCountriesSchema
			spec.DetailedTracing = true
			spec.GraphQL.Version = apidef.GraphQLConfigVersionNone
			spec.Proxy.TargetURL = testGraphQLProxyUpstream
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
		})[0]

		local.Gw.LoadAPI(testSpec)

		_, err := local.Run(
			t,
			test.TestCase{
				Path:   "/",
				Method: http.MethodPost,
				Data: gql.Request{
					Query:     gqlContinentQueryVariable,
					Variables: []byte(`{"code":null}`),
				},
				Code: 400,
			},
			test.TestCase{
				Path:   "/",
				Method: http.MethodPost,
				Data: gql.Request{
					Query:     gqlStateQueryVariable,
					Variables: []byte(`{"filter":{"code":{"eq":"filterString"}}}`),
				},
				Code: 400,
				BodyMatchFunc: func(i []byte) bool {
					return strings.Contains(string(i), `Validation for variable \"filter\" failed`)
				},
			})
		assert.NoError(t, err)
	})
}

func TestGraphQLMiddleware_EngineMode(t *testing.T) {
	assertReviewsSubgraphResponse := func(t *testing.T) func(bytes []byte) bool {
		t.Helper()
		return func(bytes []byte) bool {
			expected := `{"data":{"_entities":[{"reviews":[{"body":"A highly effective form of birth control."},{"body":"Fedoras are one of the most fashionable hats around and can look great with a variety of outfits."}]}]}}`
			var body json.RawMessage
			assert.NoError(t, json.Unmarshal(bytes, &body))

			compactBody, err := json.Marshal(body)
			assert.NoError(t, err)

			return assert.Equal(t, expected, string(compactBody))
		}
	}

	t.Run("on invalid graphql config version", func(t *testing.T) {
		g := StartTest(nil)
		defer g.Close()

		g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
			spec.GraphQL.Version = "XYZ"
		})

		t.Run("should return an error with code 500", func(t *testing.T) {
			countries1 := gql.Request{
				Query: "query Query { countries { name } }",
			}
			_, _ = g.Run(t, []test.TestCase{
				{Data: countries1, BodyMatch: `"there was a problem proxying the request`, Code: http.StatusInternalServerError},
			}...)
		})
	})

	t.Run("Inspect __typename without hitting the upstream", func(t *testing.T) {
		// See TT-6419
		g := StartTest(nil)
		defer g.Close()

		g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
			spec.GraphQL.Version = apidef.GraphQLConfigVersion2
		})

		request := gql.Request{
			Variables: nil,
			Query:     "query { __typename }",
		}

		expectedBody := []byte(`{"data":{"__typename":"Query"}}`)
		_, _ = g.Run(t, test.TestCase{
			Data: request, BodyMatchFunc: func(body []byte) bool {
				return bytes.Equal(expectedBody, body)
			},
			Code: http.StatusOK,
		})
	})

	t.Run("graphql engine v3", func(t *testing.T) {
		g := StartTest(nil)
		defer g.Close()

		t.Run("proxy only", func(t *testing.T) {
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
				spec.GraphQL.Schema = gqlProxyUpstreamSchema
				spec.GraphQL.Proxy.RequestHeaders = map[string]string{
					"Authorization": "123abc",
				}
				spec.Proxy.ListenPath = "/test"
				spec.Proxy.TargetURL = testGraphQLProxyUpstream
			})

			request := gql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			}

			_, err := g.Run(t, []test.TestCase{
				{
					Data:   request,
					Method: http.MethodPost,
					Headers: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
					},
					Path:      "/test",
					Code:      http.StatusOK,
					BodyMatch: `{"data":{"hello":"World","httpMethod":"POST"}}`,
					HeadersMatch: map[string]string{
						"Authorization": "123abc",
						"X-Tyk-Key":     "tyk-value",
						"X-Other-Key":   "other-value",
					},
				},
			}...)
			assert.NoError(t, err)
		})

		t.Run("proxy-only return errors from upstream", func(t *testing.T) {
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
				spec.GraphQL.Schema = gqlProxyUpstreamSchema
				spec.GraphQL.Proxy.UseResponseExtensions.OnErrorForwarding = true
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = testGraphQLProxyUpstreamError
			})

			request := gql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			}
			_, _ = g.Run(t, test.TestCase{
				Data:   request,
				Method: http.MethodPost,
				Code:   http.StatusInternalServerError,
				BodyMatchFunc: func(i []byte) bool {
					value, _, _, err := jsonparser.Get(i, "errors", "[0]", "extensions", "error")
					if err != nil {
						return false
					}
					return string(value) == "Something went wrong"
				},
			})
		})

		t.Run("subgraph", func(t *testing.T) {
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.Proxy.TargetURL = testSubgraphReviews
				spec.Proxy.ListenPath = "/"
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeSubgraph
				spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
				spec.GraphQL.Schema = gqlSubgraphSchemaReviews
			})

			t.Run("should execute subgraph successfully", func(t *testing.T) {
				request := gql.Request{
					Query:     gqlSubgraphQueryReviews,
					Variables: []byte(gqlSubgraphVariables),
				}

				_, _ = g.Run(t, test.TestCase{
					Data: request,
					Code: http.StatusInternalServerError,
				})
			})
		})

		t.Run("udg", func(t *testing.T) {
			ds := apidef.GraphQLEngineDataSource{}
			if err := json.Unmarshal([]byte(testRESTDataSourceConfigurationV3), &ds); err != nil {
				panic(err)
			}
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.Proxy.ListenPath = "/"
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
				spec.GraphQL.Schema = testComposedSchemaNotExtended
				spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
				spec.GraphQL.Engine.DataSources[0] = ds
				spec.GraphQL.Engine.FieldConfigs[0].DisableDefaultMapping = false
				spec.GraphQL.Engine.FieldConfigs[0].Path = []string{"data"}
			})

			t.Run("graphql api requests", func(t *testing.T) {
				countries1 := gql.Request{
					Query: "query Query { countries { name } }",
				}

				countries2 := gql.Request{
					Query: "query Query { countries { name code } }",
				}

				people1 := gql.Request{
					Query: "query Query { people { name } }",
				}

				people2 := gql.Request{
					Query: "query Query { people { country { name } name } }",
				}

				_, _ = g.Run(t, []test.TestCase{
					// GraphQL Data Source
					{Data: countries1, BodyMatch: `"countries":.*{"name":"Turkey"},{"name":"Russia"}.*`, Code: http.StatusOK},
					{Data: countries2, BodyMatch: `"countries":.*{"name":"Turkey","code":"TR"},{"name":"Russia","code":"RU"}.*`, Code: http.StatusOK},

					// REST Data Source
					{Data: people1, BodyMatch: `"people":.*{"name":"Furkan"},{"name":"Leo"}.*`, Code: http.StatusOK},
					{Data: people2, BodyMatch: `"people":.*{"country":{"name":"Turkey"},"name":"Furkan"},{"country":{"name":"Russia"},"name":"Leo"}.*`, Code: http.StatusOK},
				}...)
			})

			t.Run("introspection query", func(t *testing.T) {
				request := gql.Request{
					OperationName: "IntrospectionQuery",
					Variables:     nil,
					Query:         gqlIntrospectionQuery,
				}

				_, _ = g.Run(t, test.TestCase{Data: request, BodyMatch: `{"kind":"OBJECT","name":"Country"`, Code: http.StatusOK})
			})
		})
	})

	t.Run("graphql engine v2", func(t *testing.T) {
		g := StartTest(nil)
		defer g.Close()
		t.Run("proxy-only", func(t *testing.T) {
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
				spec.GraphQL.Schema = gqlProxyUpstreamSchema
				spec.GraphQL.Proxy.RequestHeaders = map[string]string{
					"Authorization": "123abc",
				}
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = testGraphQLProxyUpstream
			})

			request := gql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			}

			_, _ = g.Run(t, []test.TestCase{
				{
					Data:   request,
					Method: http.MethodPost,
					Headers: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
					},
					Code:      http.StatusOK,
					BodyMatch: `{"data":{"hello":"World","httpMethod":"POST"}}`,
					HeadersMatch: map[string]string{
						"Authorization": "123abc",
						"X-Tyk-Key":     "tyk-value",
						"X-Other-Key":   "other-value",
					},
				},
				{
					Data:   request,
					Method: http.MethodPut,
					Headers: map[string]string{
						"X-Tyk-Key":       "tyk-value",
						"X-Other-Key":     "other-value",
						"X-Response-Code": "201",
					},
					Code:      201,
					BodyMatch: `{"data":{"hello":"World","httpMethod":"PUT"}}`,
					HeadersMatch: map[string]string{
						"Authorization": "123abc",
						"X-Tyk-Key":     "tyk-value",
						"X-Other-Key":   "other-value",
					},
				},
			}...)
		})

		t.Run("feature use_immutable_headers", func(t *testing.T) {
			t.Run("prioritize consumer's header value when use_immutable_headers is true", func(t *testing.T) {
				// See TT-11990 && TT-12190
				g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = true
					spec.GraphQL.Enabled = true
					spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
					spec.GraphQL.Version = apidef.GraphQLConfigVersion2
					spec.GraphQL.Schema = gqlProxyUpstreamSchema
					spec.GraphQL.Proxy.Features.UseImmutableHeaders = true
					spec.GraphQL.Proxy.RequestHeaders = map[string]string{
						"Authorization": "123abc",
						"X-Tyk-Test":    "value-from-request-headers",
					}
					spec.Proxy.ListenPath = "/"
					spec.Proxy.TargetURL = testGraphQLProxyUpstream
				})

				request := gql.Request{
					Query: `{ hello(name: "World") httpMethod }`,
				}

				_, _ = g.Run(t, []test.TestCase{
					{
						Data:   request,
						Method: http.MethodPost,
						Headers: map[string]string{
							"X-Tyk-Key":   "tyk-value",
							"X-Other-Key": "other-value",
							"X-Tyk-Test":  "value-from-consumer",
						},
						Code:      http.StatusOK,
						BodyMatch: `{"data":{"hello":"World","httpMethod":"POST"}}`,
						HeadersMatch: map[string]string{
							"Authorization": "123abc",
							"X-Tyk-Key":     "tyk-value",
							"X-Other-Key":   "other-value",
							"X-Tyk-Test":    "value-from-consumer",
						},
					},
				}...)
			})

			t.Run("overwrite consumer's header value when use_immutable_headers is false (legacy behavior)", func(t *testing.T) {
				// See TT-12190
				g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = true
					spec.GraphQL.Enabled = true
					spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
					spec.GraphQL.Version = apidef.GraphQLConfigVersion2
					spec.GraphQL.Schema = gqlProxyUpstreamSchema
					spec.GraphQL.Proxy.Features.UseImmutableHeaders = false
					spec.GraphQL.Proxy.RequestHeaders = map[string]string{
						"Authorization": "123abc",
						"X-Tyk-Test":    "value-from-request-headers",
					}
					spec.Proxy.ListenPath = "/"
					spec.Proxy.TargetURL = testGraphQLProxyUpstream
				})

				request := gql.Request{
					Query: `{ hello(name: "World") httpMethod }`,
				}

				_, _ = g.Run(t, []test.TestCase{
					{
						Data:   request,
						Method: http.MethodPost,
						Headers: map[string]string{
							"X-Tyk-Key":   "tyk-value",
							"X-Other-Key": "other-value",
							"X-Tyk-Test":  "value-from-consumer",
						},
						Code:      http.StatusOK,
						BodyMatch: `{"data":{"hello":"World","httpMethod":"POST"}}`,
						HeadersMatch: map[string]string{
							"Authorization": "123abc",
							"X-Tyk-Key":     "tyk-value",
							"X-Other-Key":   "other-value",
							"X-Tyk-Test":    "value-from-request-headers",
						},
					},
				}...)
			})
		})

		t.Run("apply request headers rewrite, rule one", func(t *testing.T) {
			// Rule one:
			//
			// If header key/value is defined in request_headers_rewrite and remove
			// is set to false and client sends a request with the same header key but
			// different value, the value gets overwritten to the defined value before
			// hitting the upstream.
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
				spec.GraphQL.Schema = gqlProxyUpstreamSchema
				spec.GraphQL.Proxy.RequestHeadersRewrite = map[string]apidef.RequestHeadersRewriteConfig{
					"X-Tyk-Test": {
						Remove: false,
						Value:  "value-from-rewrite-config",
					},
				}
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = testGraphQLProxyUpstream
			})

			request := gql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			}

			_, _ = g.Run(t, []test.TestCase{
				{
					Data:   request,
					Method: http.MethodPost,
					Headers: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
						"X-Tyk-Test":  "value-from-consumer",
					},
					Code:      http.StatusOK,
					BodyMatch: `{"data":{"hello":"World","httpMethod":"POST"}}`,
					HeadersMatch: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
						"X-Tyk-Test":  "value-from-rewrite-config",
					},
				},
			}...)
		})

		t.Run("apply request headers rewrite, rule two", func(t *testing.T) {
			// Rule two:
			//
			// If header key is defined in request_headers_rewrite and remove is set
			// to true and client sends a request with the same header key but different value,
			// the headers gets removed completely before hitting the upstream.
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
				spec.GraphQL.Schema = gqlProxyUpstreamSchema
				spec.GraphQL.Proxy.RequestHeadersRewrite = map[string]apidef.RequestHeadersRewriteConfig{
					"X-Tyk-Test": {
						Remove: true,
						Value:  "value-from-rewrite-config",
					},
				}
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = testGraphQLProxyUpstream
			})

			request := gql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			}

			_, _ = g.Run(t, []test.TestCase{
				{
					Data:   request,
					Method: http.MethodPost,
					Headers: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
						"X-Tyk-Test":  "value-from-consumer",
					},
					Code:      http.StatusOK,
					BodyMatch: `{"data":{"hello":"World","httpMethod":"POST"}}`,
					HeadersMatch: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
					},
				},
			}...)
		})

		t.Run("apply request headers rewrite, rule three", func(t *testing.T) {
			// Rule three:
			//
			// If header key/value is defined in request_headers_rewrite and remove is
			// set to false and client sends a request that does not have the same header key,
			// the header key/value gets added before hitting the upstream.
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
				spec.GraphQL.Schema = gqlProxyUpstreamSchema
				spec.GraphQL.Proxy.RequestHeadersRewrite = map[string]apidef.RequestHeadersRewriteConfig{
					"X-Tyk-Test": {
						Remove: false,
						Value:  "value-from-rewrite-config",
					},
				}
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = testGraphQLProxyUpstream
			})

			request := gql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			}

			_, _ = g.Run(t, []test.TestCase{
				{
					Data:   request,
					Method: http.MethodPost,
					Headers: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
					},
					Code:      http.StatusOK,
					BodyMatch: `{"data":{"hello":"World","httpMethod":"POST"}}`,
					HeadersMatch: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
						"X-Tyk-Test":  "value-from-rewrite-config",
					},
				},
			}...)
		})

		t.Run("apply request headers rewrite, case insensitivity", func(t *testing.T) {
			// Rule one:
			//
			// If header key/value is defined in request_headers_rewrite and remove
			// is set to false and client sends a request with the same header key but
			// different value, the value gets overwritten to the defined value before
			// hitting the upstream.
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
				spec.GraphQL.Schema = gqlProxyUpstreamSchema
				spec.GraphQL.Proxy.RequestHeadersRewrite = map[string]apidef.RequestHeadersRewriteConfig{
					"X-TyK-TeSt": {
						Remove: false,
						Value:  "value-from-rewrite-config",
					},
				}
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = testGraphQLProxyUpstream
			})

			request := gql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			}

			_, _ = g.Run(t, []test.TestCase{
				{
					Data:   request,
					Method: http.MethodPost,
					Headers: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
						"X-Tyk-Test":  "value-from-consumer",
					},
					Code:      http.StatusOK,
					BodyMatch: `{"data":{"hello":"World","httpMethod":"POST"}}`,
					HeadersMatch: map[string]string{
						"X-Tyk-Key":   "tyk-value",
						"X-Other-Key": "other-value",
						"X-Tyk-Test":  "value-from-rewrite-config",
					},
				},
			}...)
		})

		t.Run("proxy-only return errors from upstream", func(t *testing.T) {
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
				spec.GraphQL.Schema = gqlProxyUpstreamSchema
				spec.GraphQL.Proxy.UseResponseExtensions.OnErrorForwarding = true
				spec.Proxy.ListenPath = "/"
				spec.Proxy.TargetURL = testGraphQLProxyUpstreamError
			})

			request := gql.Request{
				Query: `{ hello(name: "World") httpMethod }`,
			}
			_, _ = g.Run(t, test.TestCase{
				Data:   request,
				Method: http.MethodPost,
				Code:   http.StatusInternalServerError,
				BodyMatchFunc: func(i []byte) bool {
					value, _, _, err := jsonparser.Get(i, "errors", "[0]", "extensions", "error")
					if err != nil {
						return false
					}
					return string(value) == "Something went wrong"
				},
			})
		})

		t.Run("subgraph", func(t *testing.T) {
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.Proxy.TargetURL = testSubgraphReviews
				spec.Proxy.ListenPath = "/"
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeSubgraph
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
				spec.GraphQL.Schema = gqlSubgraphSchemaReviews
			})

			t.Run("should execute subgraph successfully", func(t *testing.T) {
				request := gql.Request{
					Query:     gqlSubgraphQueryReviews,
					Variables: []byte(gqlSubgraphVariables),
				}

				_, _ = g.Run(t, test.TestCase{
					Data:          request,
					BodyMatchFunc: assertReviewsSubgraphResponse(t),
					Code:          http.StatusOK,
				})
			})
		})

		t.Run("subgraph as internal data source", func(t *testing.T) {
			subgraph := BuildAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.Proxy.TargetURL = testSubgraphReviews
				spec.Proxy.ListenPath = "/internal-subgraph"
				spec.Internal = true
				spec.Name = "my-internal-subgraph"
				spec.APIID = "internal-subgraph"
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeSubgraph
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
				spec.GraphQL.Schema = gqlSubgraphSchemaReviews
			})[0]

			proxyOnlyAPI := BuildAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.Proxy.TargetURL = "tyk://" + subgraph.Name
				spec.Proxy.ListenPath = "/"
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
				spec.GraphQL.Schema = gqlSubgraphSchemaReviews
			})[0]

			g.Gw.LoadAPI(subgraph, proxyOnlyAPI)

			t.Run("should execute internal subgraph successfully", func(t *testing.T) {
				request := gql.Request{
					Query:     gqlSubgraphQueryReviews,
					Variables: []byte(gqlSubgraphVariables),
				}

				_, _ = g.Run(t, test.TestCase{
					Data:          request,
					BodyMatchFunc: assertReviewsSubgraphResponse(t),
					Code:          http.StatusOK,
				})
			})
		})

		t.Run("udg", func(t *testing.T) {
			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.Proxy.ListenPath = "/"
				spec.GraphQL.Enabled = true
				spec.GraphQL.Schema = testComposedSchemaNotExtended
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
			})

			t.Run("graphql api requests", func(t *testing.T) {
				//countries1 := gql.Request{
				//	Query: "query Query { countries { name } }",
				//}
				//
				//countries2 := gql.Request{
				//	Query: "query Query { countries { name code } }",
				//}

				people1 := gql.Request{
					Query: "query Query { people { name } }",
				}

				//people2 := gql.Request{
				//	Query: "query Query { people { country { name } name } }",
				//}

				_, _ = g.Run(t, []test.TestCase{
					// GraphQL Data Source
					//{Data: countries1, BodyMatch: `"countries":.*{"name":"Turkey"},{"name":"Russia"}.*`, Code: http.StatusOK},
					//{Data: countries2, BodyMatch: `"countries":.*{"name":"Turkey","code":"TR"},{"name":"Russia","code":"RU"}.*`, Code: http.StatusOK},

					// REST Data Source
					{Data: people1, BodyMatch: `"people":.*{"name":"Furkan"},{"name":"Leo"}.*`, Code: http.StatusOK},
					//{Data: people2, BodyMatch: `"people":.*{"country":{"name":"Turkey"},"name":"Furkan"},{"country":{"name":"Russia"},"name":"Leo"}.*`, Code: http.StatusOK},
				}...)
			})

			t.Run("introspection query", func(t *testing.T) {
				request := gql.Request{
					OperationName: "IntrospectionQuery",
					Variables:     nil,
					Query:         gqlIntrospectionQuery,
				}

				_, _ = g.Run(t, test.TestCase{Data: request, BodyMatch: `{"kind":"OBJECT","name":"Country"`, Code: http.StatusOK})
			})
		})

		t.Run("websockets", func(t *testing.T) {
			cfg := g.Gw.GetConfig()
			cfg.HttpServerOptions.EnableWebSockets = true
			g.Gw.SetConfig(cfg)

			baseURL := strings.Replace(g.URL, "http://", "ws://", -1)
			api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.Proxy.ListenPath = "/"
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
			})[0]

			t.Run("on disabled websockets", func(t *testing.T) {
				cfg := g.Gw.GetConfig()
				cfg.HttpServerOptions.EnableWebSockets = false
				g.Gw.SetConfig(cfg)

				t.Run("should respond with 422 when trying to upgrade to websockets", func(t *testing.T) {
					_, _ = g.Run(t, []test.TestCase{
						{
							Headers: map[string]string{
								header.Connection:           "upgrade",
								header.Upgrade:              "websocket",
								header.SecWebSocketProtocol: "graphql-ws",
								header.SecWebSocketVersion:  "13",
								header.SecWebSocketKey:      "123abc",
							},
							Code:      http.StatusUnprocessableEntity,
							BodyMatch: "websockets are not allowed",
						},
					}...)
				})
			})

			t.Run("on enabled websockets", func(t *testing.T) {
				cfg := g.Gw.GetConfig()
				cfg.HttpServerOptions.EnableWebSockets = true
				g.Gw.SetConfig(cfg)

				t.Run("should deny upgrade with 400 when protocol is not graphql-ws or graphql-transport-ws", func(t *testing.T) {
					_, _ = g.Run(t, []test.TestCase{
						{
							Headers: map[string]string{
								header.Connection:           "upgrade",
								header.Upgrade:              "websocket",
								header.SecWebSocketProtocol: "invalid",
								header.SecWebSocketVersion:  "13",
								header.SecWebSocketKey:      "123abc",
							},
							Code:      http.StatusBadRequest,
							BodyMatch: "invalid websocket protocol for upgrading to a graphql websocket connection",
						},
					}...)
				})

				t.Run("should upgrade to websocket connection with correct protocol", func(t *testing.T) {
					t.Run("graphql-ws", func(t *testing.T) {
						wsConn, _, err := websocket.DefaultDialer.Dial(baseURL, map[string][]string{
							header.SecWebSocketProtocol: {string(gqlwebsocket.ProtocolGraphQLWS)},
						})
						require.NoError(t, err)
						defer wsConn.Close()

						// Send a connection init message to gateway
						err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"type":"connection_init","payload":{}}`))
						require.NoError(t, err)

						_, msg, err := wsConn.ReadMessage()

						// Gateway should acknowledge the connection
						assert.Equal(t, `{"type":"connection_ack"}`, string(msg))
						assert.NoError(t, err)
					})
					t.Run("graphql-transport-ws", func(t *testing.T) {
						wsConn, _, err := websocket.DefaultDialer.Dial(baseURL, map[string][]string{
							header.SecWebSocketProtocol: {string(gqlwebsocket.ProtocolGraphQLTransportWS)},
						})
						require.NoError(t, err)
						defer wsConn.Close()

						// Send a connection init message to gateway
						err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"type":"connection_init"}`))
						require.NoError(t, err)

						_, msg, err := wsConn.ReadMessage()

						// Gateway should acknowledge the connection
						assert.Equal(t, `{"type":"connection_ack"}`, string(msg))
						assert.NoError(t, err)
					})

				})

				t.Run("graphql over websockets", func(t *testing.T) {
					api.UseKeylessAccess = false
					g.Gw.LoadAPI(api)

					t.Run("field-based permissions", func(t *testing.T) {
						_, directKey := g.CreateSession(func(s *user.SessionState) {
							s.AccessRights = map[string]user.AccessDefinition{
								api.APIID: {
									APIID:   api.APIID,
									APIName: api.Name,
									RestrictedTypes: []gql.Type{
										{
											Name:   "Query",
											Fields: []string{"countries"},
										},
									},
								},
							}
						})

						wsConn, _, err := websocket.DefaultDialer.Dial(baseURL, map[string][]string{
							header.SecWebSocketProtocol: {string(gqlwebsocket.ProtocolGraphQLWS)},
							header.Authorization:        {directKey},
						})
						require.NoError(t, err)
						defer wsConn.Close()

						// Send a connection init message to gateway
						err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"type":"connection_init","payload":{}}`))
						require.NoError(t, err)

						_, msg, err := wsConn.ReadMessage()

						// Gateway should acknowledge the connection
						require.Equal(t, `{"type":"connection_ack"}`, string(msg))
						require.NoError(t, err)

						err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"id": "1", "type": "start", "payload": {"query": "{ countries { name } }", "variables": null}}`))
						require.NoError(t, err)

						_, msg, err = wsConn.ReadMessage()
						assert.Equal(t, `{"id":"1","type":"error","payload":[{"message":"field: countries is restricted on type: Query"}]}`, string(msg))
						assert.NoError(t, err)
					})

					t.Run("depth limit", func(t *testing.T) {
						_, directKey := g.CreateSession(func(s *user.SessionState) {
							s.AccessRights = map[string]user.AccessDefinition{
								api.APIID: {
									APIID:   api.APIID,
									APIName: api.Name,
									Limit:   user.APILimit{MaxQueryDepth: 1},
								},
							}
						})

						wsConn, _, err := websocket.DefaultDialer.Dial(baseURL, map[string][]string{
							header.SecWebSocketProtocol: {string(gqlwebsocket.ProtocolGraphQLWS)},
							header.Authorization:        {directKey},
						})
						require.NoError(t, err)
						defer wsConn.Close()

						// Send a connection init message to gateway
						err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"type":"connection_init","payload":{}}`))
						require.NoError(t, err)

						_, msg, err := wsConn.ReadMessage()

						// Gateway should acknowledge the connection
						require.Equal(t, `{"type":"connection_ack"}`, string(msg))
						require.NoError(t, err)

						err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"id": "1", "type": "start", "payload": {"query": "{ countries { name } }", "variables": null}}`))
						require.NoError(t, err)

						_, msg, err = wsConn.ReadMessage()
						assert.Equal(t, `{"id":"1","type":"error","payload":[{"message":"depth limit exceeded"}]}`, string(msg))
						assert.NoError(t, err)
					})
				})

				t.Run("should send configured headers upstream", func(t *testing.T) {
					run := func(apiSpec func(testServerURL string) func(apiSpec *APISpec), requestHeaders, expectedHeaders http.Header) func(t *testing.T) {
						return func(t *testing.T) {
							t.Helper()
							wg := sync.WaitGroup{}
							wg.Add(2)

							wsTestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								defer wg.Done()
								for expectedHeaderKey := range expectedHeaders {
									values := r.Header.Values(expectedHeaderKey)
									headerExists := assert.Greater(t, len(values), 0, fmt.Sprintf("no header values found for header '%s'", expectedHeaderKey))
									if !headerExists {
										return
									}
									for _, expectedHeaderValue := range expectedHeaders[expectedHeaderKey] {
										assert.Contains(t, values, expectedHeaderValue, fmt.Sprintf("expected header value '%s' was not found for '%s'", expectedHeaderValue, expectedHeaderKey))
									}
								}
								_, _ = w.Write(nil)
							}))
							defer wsTestServer.Close()

							g.Gw.BuildAndLoadAPI(apiSpec(wsTestServer.URL))

							wsConnHeaders := http.Header{
								header.SecWebSocketProtocol: {string(gqlwebsocket.ProtocolGraphQLWS)},
							}

							for key, value := range requestHeaders {
								wsConnHeaders.Set(key, value[0])
							}

							wsConn, _, err := websocket.DefaultDialer.Dial(baseURL, wsConnHeaders)
							require.NoError(t, err)
							defer wsConn.Close()

							// Send a connection init message to gateway
							err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"type":"connection_init"}`))
							require.NoError(t, err)

							// Gateway should acknowledge the connection
							_, msg, err := wsConn.ReadMessage()
							require.Equal(t, `{"type":"connection_ack"}`, string(msg))
							require.NoError(t, err)

							// Start subscription
							err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"id":"1","type":"start","payload":{"query":"subscription { subscribe }"}}`))
							require.NoError(t, err)

							// wait for assertions to be done
							wg.Done()
							wg.Wait()
						}
					}

					t.Run("for proxy-only", run(
						func(testServerURL string) func(apiSpec *APISpec) {
							return func(spec *APISpec) {
								spec.UseKeylessAccess = true
								spec.Proxy.ListenPath = "/"
								spec.EnableContextVars = true
								spec.GraphQL.Enabled = true
								spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
								spec.GraphQL.Version = apidef.GraphQLConfigVersion2
								spec.GraphQL.Schema = `type Query { hello: String } type Subscription { subscribe: String }`
								spec.GraphQL.Proxy.RequestHeaders = map[string]string{
									"My-Custom-Header": "custom-value",
									"From-Request":     "$tyk_context.headers_X_My_Request",
								}
								spec.Proxy.TargetURL = testServerURL
							}
						},
						http.Header{
							"X-My-Request": {"request-value"},
						},
						http.Header{
							"My-Custom-Header": {"custom-value"},
							"From-Request":     {"request-value"},
						},
					))

					t.Run("for udg", run(
						func(testServerURL string) func(apiSpec *APISpec) {
							return func(spec *APISpec) {
								spec.UseKeylessAccess = true
								spec.Proxy.ListenPath = "/"
								spec.EnableContextVars = true
								spec.GraphQL.Enabled = true
								spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
								spec.GraphQL.Version = apidef.GraphQLConfigVersion2
								spec.GraphQL.Schema = `type Query { hello: String } type Subscription { subscribe: String }`
								spec.GraphQL.Engine.GlobalHeaders = []apidef.UDGGlobalHeader{
									{
										Key:   "Global-Key",
										Value: "global-value",
									},
									{
										Key:   "Already-Used-Key",
										Value: "global-used-value",
									},
								}
								spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
									{
										Kind:     apidef.GraphQLEngineDataSourceKindGraphQL,
										Name:     "ds",
										Internal: false,
										RootFields: []apidef.GraphQLTypeFields{
											{
												Type:   "Subscription",
												Fields: []string{"subscribe"},
											},
										},
										Config: []byte(fmt.Sprintf(`{
											"url": "%s",
											"method": "POST",
											"headers": {
												"Already-Used-Key": "local-used-value",
												"Local-Key": "local-value",
												"Context-Key": "$tyk_context.headers_X_My_Request"
											}
										}`, testServerURL)),
									},
								}
							}
						},
						http.Header{
							"X-My-Request": {"request-value"},
						},
						http.Header{
							"Already-Used-Key": {"local-used-value"},
							"Local-Key":        {"local-value"},
							"Context-Key":      {"request-value"},
							"Global-Key":       {"global-value"},
						},
					))
				})
			})
		})
	})

	t.Run("graphql engine v1", func(t *testing.T) {
		g := StartTest(nil)
		defer g.Close()

		api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		})[0]

		t.Run("graphql api requests", func(t *testing.T) {
			countries1 := gql.Request{
				Query: "query Query { countries { name } }",
			}

			countries2 := gql.Request{
				Query: "query Query { countries { name code } }",
			}

			people1 := gql.Request{
				Query: "query Query { people { name } }",
			}

			people2 := gql.Request{
				Query: "query Query { people { country { name } name } }",
			}

			_, _ = g.Run(t, []test.TestCase{
				// GraphQL Data Source
				{Data: countries1, BodyMatch: `"countries":.*{"name":"Turkey"},{"name":"Russia"}.*`, Code: http.StatusOK},
				{Data: countries2, BodyMatch: `"countries":.*{"name":"Turkey","code":"TR"},{"name":"Russia","code":"RU"}.*`, Code: http.StatusOK},

				// REST Data Source
				{Data: people1, BodyMatch: `"people":.*{"name":"Furkan"},{"name":"Leo"}.*`, Code: http.StatusOK},
				{Data: people2, BodyMatch: `"people":.*{"country":{"name":"Turkey"},"name":"Furkan"},{"country":{"name":"Russia"},"name":"Leo"}.*`, Code: http.StatusOK},
			}...)
		})

		t.Run("introspection query", func(t *testing.T) {
			request := gql.Request{
				OperationName: "IntrospectionQuery",
				Variables:     nil,
				Query:         gqlIntrospectionQuery,
			}

			_, _ = g.Run(t, test.TestCase{Data: request, BodyMatch: `{"kind":"OBJECT","name":"Country"`, Code: http.StatusOK})
		})

		t.Run("should return error when supergraph is used with v1", func(t *testing.T) {
			api.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeSupergraph
			g.Gw.LoadAPI(api)

			request := gql.Request{
				Query: "query Query { countries { name } }",
			}

			_, _ = g.Run(t, test.TestCase{Data: request, BodyMatch: `there was a problem proxying the request`, Code: http.StatusInternalServerError})
		})

		t.Run("websockets", func(t *testing.T) {
			api.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
			g.Gw.LoadAPI(api)

			t.Run("on disabled websockets", func(t *testing.T) {
				cfg := g.Gw.GetConfig()
				cfg.HttpServerOptions.EnableWebSockets = false
				g.Gw.SetConfig(cfg)

				t.Run("should respond with 422 when trying to upgrade to websockets", func(t *testing.T) {
					_, _ = g.Run(t, []test.TestCase{
						{
							Headers: map[string]string{
								header.Connection:           "upgrade",
								header.Upgrade:              "websocket",
								header.SecWebSocketProtocol: "graphql-ws",
								header.SecWebSocketVersion:  "13",
								header.SecWebSocketKey:      "123abc",
							},
							Code:      http.StatusUnprocessableEntity,
							BodyMatch: "websockets are not allowed",
						},
					}...)
				})
			})

			t.Run("on enabled websockets", func(t *testing.T) {
				cfg := g.Gw.GetConfig()
				cfg.HttpServerOptions.EnableWebSockets = true
				g.Gw.SetConfig(cfg)

				t.Run("should respond with 422 when trying to upgrade to websockets", func(t *testing.T) {
					_, _ = g.Run(t, []test.TestCase{
						{
							Headers: map[string]string{
								header.Connection:           "upgrade",
								header.Upgrade:              "websocket",
								header.SecWebSocketProtocol: "graphql-ws",
								header.SecWebSocketVersion:  "13",
								header.SecWebSocketKey:      "123abc",
							},
							Code:      http.StatusUnprocessableEntity,
							BodyMatch: "websockets are not allowed",
						},
					}...)
				})
			})
		})
	})
}

func TestNeedsGraphQLExecutionEngine(t *testing.T) {
	testCases := []struct {
		name          string
		version       apidef.GraphQLConfigVersion
		executionMode apidef.GraphQLExecutionMode
		expected      bool
	}{
		{
			name:          "true for executionMode = executionEngine in v2",
			version:       apidef.GraphQLConfigVersion2,
			executionMode: apidef.GraphQLExecutionModeExecutionEngine,
			expected:      true,
		},
		{
			name:          "true for executionMode = supergraph in v2",
			version:       apidef.GraphQLConfigVersion2,
			executionMode: apidef.GraphQLExecutionModeSupergraph,
			expected:      true,
		},
		{
			name:          "true for executionMode = subgraph in v2",
			version:       apidef.GraphQLConfigVersion2,
			executionMode: apidef.GraphQLExecutionModeExecutionEngine,
			expected:      true,
		},
		{
			name:          "true for executionMode = proxyOnly in v2",
			version:       apidef.GraphQLConfigVersion2,
			executionMode: apidef.GraphQLExecutionModeProxyOnly,
			expected:      true,
		},
		{
			name:          "true for executionMode = executionEngine in v1",
			version:       apidef.GraphQLConfigVersion1,
			executionMode: apidef.GraphQLExecutionModeExecutionEngine,
			expected:      true,
		},
		{
			name:          "false for executionMode = proxyOnly in v1",
			version:       apidef.GraphQLConfigVersion1,
			executionMode: apidef.GraphQLExecutionModeProxyOnly,
			expected:      false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			apiSpec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					GraphQL: apidef.GraphQLConfig{
						Enabled:       true,
						Version:       tc.version,
						ExecutionMode: tc.executionMode,
					},
				},
			}

			result := needsGraphQLExecutionEngine(apiSpec)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsGraphQLProxyOnly(t *testing.T) {
	testCases := []struct {
		name          string
		executionMode apidef.GraphQLExecutionMode
		expected      bool
	}{
		{
			name:          "true for executionMode = proxyOnly",
			executionMode: apidef.GraphQLExecutionModeProxyOnly,
			expected:      true,
		},
		{
			name:          "true for executionMode = subgraph",
			executionMode: apidef.GraphQLExecutionModeSubgraph,
			expected:      true,
		},
		{
			name:          "false for executionMode = supergraph",
			executionMode: apidef.GraphQLExecutionModeSupergraph,
			expected:      false,
		},
		{
			name:          "false for executionMode = executionEngine",
			executionMode: apidef.GraphQLExecutionModeExecutionEngine,
			expected:      false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			apiSpec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					GraphQL: apidef.GraphQLConfig{
						Enabled:       true,
						ExecutionMode: tc.executionMode,
					},
				},
			}

			result := isGraphQLProxyOnly(apiSpec)
			assert.Equal(t, tc.expected, result)
		})
	}
}

const gqlIntrospectionQuery = `query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}`

const gqlProxyUpstreamSchema = `type Query {
	hello(name: String!): String!
	httpMethod: String!
}`

const gqlCountriesSchema = `directive @cacheControl(
  maxAge: Int
  scope: CacheControlScope
) on FIELD_DEFINITION | OBJECT | INTERFACE
enum CacheControlScope {
  PUBLIC
  PRIVATE
}

type Continent {
  code: ID!
  name: String!
  countries: [Country!]!
}

input ContinentFilterInput {
  code: StringQueryOperatorInput
}

type Country {
  code: ID!
  name: String!
  native: String!
  phone: String!
  continent: Continent!
  capital: String
  currency: String
  languages: [Language!]!
  emoji: String!
  emojiU: String!
  states: [State!]!
}

input CountryFilterInput {
  code: StringQueryOperatorInput
  currency: StringQueryOperatorInput
  continent: StringQueryOperatorInput
}

type Language {
  code: ID!
  name: String
  native: String
  rtl: Boolean!
}

input LanguageFilterInput {
  code: StringQueryOperatorInput
}

input StateFilterInput{
  code: StringQueryOperatorInput
  compulsory: String!
}

type Query {
  continents(filter: ContinentFilterInput): [Continent!]!
  continent(code: ID!): Continent
  countries(filter: CountryFilterInput): [Country!]!
  country(code: ID!): Country
  languages(filter: LanguageFilterInput): [Language!]!
  language(code: ID!): Language
  state(filter: StateFilterInput): [State!]!
}

type State {
  code: String
  name: String!
  country: Country!
}

input StringQueryOperatorInput {
  eq: String
  ne: String
  in: [String]
  nin: [String]
  regex: String
  glob: String
}

scalar Upload`

const (
	gqlContinentQuery = `
query {
    continent(code: "NG"){
        code
        name
    }
}
`
	gqlContinentQueryVariable = `
query ($code: ID!){
    continent(code: $code){
        name
    }
}`
	gqlStateQueryVariable = `
query ($filter: StateFilterInput) {
  state(filter: $filter) {
    name
  }
}`
)

const gqlSubgraphSchemaAccounts = `scalar _Any
scalar _FieldSet
union _Entity = User

type _Service {
  sdl: String
}

type Query {
  me: User
  allUsers: [User]
  _entities(representations: [_Any!]!): [_Entity]!
  _service: _Service!
}

type User @key(fields: "id"){ 
	id: ID! 
	username: String!
}

directive @external on FIELD_DEFINITION
directive @requires(fields: _FieldSet!) on FIELD_DEFINITION
directive @provides(fields: _FieldSet!) on FIELD_DEFINITION
directive @key(fields: _FieldSet!) on OBJECT | INTERFACE
directive @extends on OBJECT | INTERFACE`

const gqlSubgraphSDLAccounts = `extend type Query {
	me: User
	allUsers: [User]
} 

type User @key(fields: "id") { 
	id: ID! 
	username: String!
}`

const gqlSubgraphSDLBankAccounts = `
extend type User @key(fields: "id") {
  id: ID! @extends
  account: [BankAccount!]
}

type BankAccount {
  number: String
  balance: Float
}
`

const gqlSubgraphSchemaBankAccounts = `
extend type User @key(fields: "id"){
    id: ID! @extends
    account: [BankAccount!]
}

type BankAccount {
    number: String
    balance: Float 
}

scalar _Any
scalar _FieldSet
union _Entity = User

type _Service {
  sdl: String
}

type Query {
  _entities(representations: [_Any!]!): [_Entity]!
  _service: _Service!
}

type BankAccount {
    number: String
    balance: Float 
}

type User @key(fields: "id"){
    id: ID! @extends
    account: [BankAccount!]
}

directive @external on FIELD_DEFINITION
directive @requires(fields: _FieldSet!) on FIELD_DEFINITION
directive @provides(fields: _FieldSet!) on FIELD_DEFINITION
directive @key(fields: _FieldSet!) on OBJECT | INTERFACE
directive @extends on OBJECT | INTERFACE`

const gqlSubgraphSchemaReviews = `scalar _Any
scalar _FieldSet
union _Entity = User | Product

type _Service {
  sdl: String
}

type Query {
  _entities(representations: [_Any!]!): [_Entity]!
  _service: _Service!
}

type Review {
	body: String!
	author: User! @provides(fields: "username")
	product: Product!
}

type User @key(fields: "id") {
	id: ID! @external
	reviews: [Review]
}

type Product @key(fields: "upc") {
	upc: String! @external
	name: String! @external
	reviews: [Review] @requires(fields: "name")
}

directive @external on FIELD_DEFINITION
directive @requires(fields: _FieldSet!) on FIELD_DEFINITION
directive @provides(fields: _FieldSet!) on FIELD_DEFINITION
directive @key(fields: _FieldSet!) on OBJECT | INTERFACE
directive @extends on OBJECT | INTERFACE`

const gqlSubgraphSDLReviews = `type Review {
	body: String!
	author: User! @provides(fields: "username")
	product: Product!
}

extend type User @key(fields: "id") {
	id: ID! @external
	reviews: [Review]
}

extend type Product @key(fields: "upc") {
	upc: String! @external
	reviews: [Review]
}`

const gqlSubgraphQueryReviews = `query Subgraph($_representations: [_Any!]!) {
  _entities(representations: $_representations) {
    ... on User {
      reviews {
		body
	  }
    }
  }
}`

const gqlSubgraphVariables = `{
	"_representations": [
		{
			"__typename": "User",
			"id": "1"
		}
	]
}`

const gqlMergedSupergraphSDL = `type Query {
	me: User
	allUsers: [User]
	topProducts(first: Int = 5): [Product]
}

type Subscription {
	review: Review!
}

type User {
	id: ID!
	username: String!
	reviews: [Review]
	account: [BankAccount!]
}

type BankAccount {
    number: String
    balance: Float 
}

type Product {
	upc: String!
	name: String!
	price: Int!
	reviews: [Review]
}

type Review {
	body: String!
	author: User!
	product: Product!
}`
