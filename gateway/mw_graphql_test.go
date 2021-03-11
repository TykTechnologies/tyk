package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/user"

	gql "github.com/jensneuse/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/test"
)

// Note: here we test only validation behaviour and do not expect real graphql responses here
func TestGraphQLMiddleware_RequestValidation(t *testing.T) {
	g := StartTest()
	defer g.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
	})[0]

	t.Run("Bad schema", func(t *testing.T) {
		spec.GraphQL.Schema = "query: Query"
		LoadAPI(spec)

		_, _ = g.Run(t, test.TestCase{BodyMatch: "there was a problem proxying the request", Code: http.StatusInternalServerError})
	})

	t.Run("Introspection query with custom query type should successfully work", func(t *testing.T) {
		spec.GraphQL.Schema = "schema { query: query_root } type query_root { hello: word } type word { numOfLetters: Int }"
		LoadAPI(spec)

		request := gql.Request{
			OperationName: "IntrospectionQuery",
			Variables:     nil,
			Query:         gqlIntrospectionQuery,
		}

		_, _ = g.Run(t, test.TestCase{Data: request, BodyMatch: "__schema", Code: http.StatusOK})
	})

	t.Run("Empty request shouldn't be unmarshalled", func(t *testing.T) {
		spec.GraphQL.Schema = "schema { query: Query } type Query { hello: word } type word { numOfLetters: Int }"
		LoadAPI(spec)

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
		LoadAPI(spec)

		pID := CreatePolicy(func(p *user.Policy) {
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
			headers.Authorization: directKey,
		}

		authHeaderWithPolicyAppliedKey := map[string]string{
			headers.Authorization: policyAppliedKey,
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
				_ = GlobalSessionManager.UpdateSession(directKey, directSession, 0, false)

				_, _ = g.Run(t, test.TestCase{Headers: authHeaderWithDirectKey, Data: request, BodyMatch: "hello", Code: http.StatusOK})
			})

			t.Run("-1", func(t *testing.T) {
				directSession.MaxQueryDepth = -1
				_ = GlobalSessionManager.UpdateSession(directKey, directSession, 0, false)

				_, _ = g.Run(t, test.TestCase{Headers: authHeaderWithDirectKey, Data: request, BodyMatch: "hello", Code: http.StatusOK})
			})
		})

		t.Run("Valid query should successfully work", func(t *testing.T) {
			directSession.MaxQueryDepth = 2
			_ = GlobalSessionManager.UpdateSession(directKey, directSession, 0, false)

			_, _ = g.Run(t, test.TestCase{Headers: authHeaderWithDirectKey, Data: request, BodyMatch: "hello", Code: http.StatusOK})
		})

		t.Run("Invalid query should return 403 when auth is failing", func(t *testing.T) {
			request.Query = "query Hello {"
			authHeaderWithInvalidDirectKey := map[string]string{
				headers.Authorization: "invalid key",
			}
			_, _ = g.Run(t, test.TestCase{Headers: authHeaderWithInvalidDirectKey, Data: request, BodyMatch: "", Code: http.StatusForbidden})
		})
	})
}

func TestGraphQLMiddleware_EngineMode(t *testing.T) {
	g := StartTest()
	defer g.Close()

	t.Run("on invalid graphql config version", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
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
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
			spec.GraphQL.Version = apidef.GraphQLConfigVersion2
		})

		t.Run("on disabled websockets", func(t *testing.T) {
			cfg := config.Global()
			cfg.HttpServerOptions.EnableWebSockets = false
			config.SetGlobal(cfg)

			t.Run("should respond with 422 when trying to upgrade to websockets", func(t *testing.T) {
				_, _ = g.Run(t, []test.TestCase{
					{
						Headers: map[string]string{
							headers.Connection:           "upgrade",
							headers.Upgrade:              "websocket",
							headers.SecWebSocketProtocol: "graphql-ws",
							headers.SecWebSocketVersion:  "13",
							headers.SecWebSocketKey:      "123abc",
						},
						Code:      http.StatusUnprocessableEntity,
						BodyMatch: "websockets are not allowed",
					},
				}...)
			})
		})

		t.Run("graphql websocket upgrade", func(t *testing.T) {
			cfg := config.Global()
			cfg.HttpServerOptions.EnableWebSockets = true
			config.SetGlobal(cfg)

			t.Run("should deny upgrade with 400 when protocol is not graphql-ws", func(t *testing.T) {
				_, _ = g.Run(t, []test.TestCase{
					{
						Headers: map[string]string{
							headers.Connection:           "upgrade",
							headers.Upgrade:              "websocket",
							headers.SecWebSocketProtocol: "invalid",
							headers.SecWebSocketVersion:  "13",
							headers.SecWebSocketKey:      "123abc",
						},
						Code:      http.StatusBadRequest,
						BodyMatch: "invalid websocket protocol for upgrading to a graphql websocket connection",
					},
				}...)
			})

			t.Run("should upgrade to websocket connection with correct protocol", func(t *testing.T) {
				baseURL := strings.Replace(g.URL, "http://", "ws://", -1)
				wsConn, _, err := websocket.DefaultDialer.Dial(baseURL, map[string][]string{
					headers.SecWebSocketProtocol: {GraphQLWebSocketProtocol},
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

	t.Run("graphql engine v1", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		})

		t.Run("on disabled websockets", func(t *testing.T) {
			cfg := config.Global()
			cfg.HttpServerOptions.EnableWebSockets = false
			config.SetGlobal(cfg)

			t.Run("should respond with 422 when trying to upgrade to websockets", func(t *testing.T) {
				_, _ = g.Run(t, []test.TestCase{
					{
						Headers: map[string]string{
							headers.Connection:           "upgrade",
							headers.Upgrade:              "websocket",
							headers.SecWebSocketProtocol: "graphql-ws",
							headers.SecWebSocketVersion:  "13",
							headers.SecWebSocketKey:      "123abc",
						},
						Code:      http.StatusUnprocessableEntity,
						BodyMatch: "websockets are not allowed",
					},
				}...)
			})
		})

		t.Run("graphql websocket upgrade", func(t *testing.T) {
			cfg := config.Global()
			cfg.HttpServerOptions.EnableWebSockets = true
			config.SetGlobal(cfg)

			t.Run("should deny upgrade with 400 when protocol is not graphql-ws", func(t *testing.T) {
				_, _ = g.Run(t, []test.TestCase{
					{
						Headers: map[string]string{
							headers.Connection:           "upgrade",
							headers.Upgrade:              "websocket",
							headers.SecWebSocketProtocol: "invalid",
							headers.SecWebSocketVersion:  "13",
							headers.SecWebSocketKey:      "123abc",
						},
						Code:      http.StatusBadRequest,
						BodyMatch: "invalid websocket protocol for upgrading to a graphql websocket connection",
					},
				}...)
			})

			t.Run("should upgrade to websocket connection with correct protocol", func(t *testing.T) {
				baseURL := strings.Replace(g.URL, "http://", "ws://", -1)
				wsConn, _, err := websocket.DefaultDialer.Dial(baseURL, map[string][]string{
					headers.SecWebSocketProtocol: {GraphQLWebSocketProtocol},
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
