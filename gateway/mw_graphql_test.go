package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

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
}

func TestGraphQLMiddleware_EngineMode(t *testing.T) {
	assertReviewsSubgraphResponse := func(t *testing.T) func(bytes []byte) bool {
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
				{Data: countries1, BodyMatch: `"There was a problem proxying the request`, Code: http.StatusInternalServerError},
			}...)
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
				spec.GraphQL.Proxy.AuthHeaders = map[string]string{
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
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
				spec.GraphQL.Version = apidef.GraphQLConfigVersion2
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

		t.Run("websockets", func(t *testing.T) {
			cfg := g.Gw.GetConfig()
			cfg.HttpServerOptions.EnableWebSockets = true
			g.Gw.SetConfig(cfg)

			baseURL := strings.Replace(g.URL, "http://", "ws://", -1)
			api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = true
				spec.Proxy.ListenPath = "/"
				spec.GraphQL.Enabled = true
				spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
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

				t.Run("should deny upgrade with 400 when protocol is not graphql-ws", func(t *testing.T) {
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
					wsConn, _, err := websocket.DefaultDialer.Dial(baseURL, map[string][]string{
						header.SecWebSocketProtocol: {GraphQLWebSocketProtocol},
					})
					require.NoError(t, err)
					defer wsConn.Close()

					// Send a connection init message to gateway
					err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"type":"connection_init","payload":{}}`))
					require.NoError(t, err)

					_, msg, err := wsConn.ReadMessage()

					// Gateway should acknowledge the connection
					assert.Equal(t, `{"id":"","type":"connection_ack","payload":null}`, string(msg))
					assert.NoError(t, err)
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
							header.SecWebSocketProtocol: {GraphQLWebSocketProtocol},
							header.Authorization:        {directKey},
						})
						require.NoError(t, err)
						defer wsConn.Close()

						// Send a connection init message to gateway
						err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"type":"connection_init","payload":{}}`))
						require.NoError(t, err)

						_, msg, err := wsConn.ReadMessage()

						// Gateway should acknowledge the connection
						require.Equal(t, `{"id":"","type":"connection_ack","payload":null}`, string(msg))
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
							header.SecWebSocketProtocol: {GraphQLWebSocketProtocol},
							header.Authorization:        {directKey},
						})
						require.NoError(t, err)
						defer wsConn.Close()

						// Send a connection init message to gateway
						err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"type":"connection_init","payload":{}}`))
						require.NoError(t, err)

						_, msg, err := wsConn.ReadMessage()

						// Gateway should acknowledge the connection
						require.Equal(t, `{"id":"","type":"connection_ack","payload":null}`, string(msg))
						require.NoError(t, err)

						err = wsConn.WriteMessage(websocket.BinaryMessage, []byte(`{"id": "1", "type": "start", "payload": {"query": "{ countries { name } }", "variables": null}}`))
						require.NoError(t, err)

						_, msg, err = wsConn.ReadMessage()
						assert.Equal(t, `{"id":"1","type":"error","payload":[{"message":"depth limit exceeded"}]}`, string(msg))
						assert.NoError(t, err)
					})
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

type Query {
  continents(filter: ContinentFilterInput): [Continent!]!
  continent(code: ID!): Continent
  countries(filter: CountryFilterInput): [Country!]!
  country(code: ID!): Country
  languages(filter: LanguageFilterInput): [Language!]!
  language(code: ID!): Language
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
