//go:build ee || dev

package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buger/jsonparser"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter/gqlengineadapter/enginev3"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

func TestGraphQLMiddleware_UDGFederation(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/1" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id": "1", "username": "alice"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindREST,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{
						Type:   "User",
						Fields: []string{"id", "username"},
					},
				},
				Config: []byte(fmt.Sprintf(`{
						"url": "%s/users/{{ .object.id }}",
						"method": "GET"
					}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	query := `
			query($representations: [_Any!]!) {
				_entities(representations: $representations) {
					... on User {
						id
						username
					}
				}
			}
		`
	variables := `{"representations": [{"__typename": "User", "id": "1"}]}`

	body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	require.Contains(t, string(resBody), `"id":"1"`)
	require.Contains(t, string(resBody), `"username":"alice"`)
}

// TestGraphQLMiddleware_UDGFederation_ServiceQuery regression-tests the bug
// where `{ _service { sdl } }` returned HTTP 500 in UDG mode because the
// static service data source had no ChildNodes for `_Service.sdl`. Apollo
// Router / `rover dev` / WunderGraph Cosmo all fire `_service { sdl }` as the
// very first query during schema discovery, so a 500 here blocks Tyk from
// being composed as a federation v2 subgraph.
func TestGraphQLMiddleware_UDGFederation_ServiceQuery(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// _service { sdl } is fully resolved from the static datasource — the
		// REST upstream should never be hit. We still register it so the API
		// definition is realistic.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	customerSchema := `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = customerSchema
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindREST,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{
						Type:   "User",
						Fields: []string{"id", "username"},
					},
				},
				Config: []byte(fmt.Sprintf(`{
						"url": "%s/users/{{ .object.id }}",
						"method": "GET"
					}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	body := `{"query": "{ _service { sdl } }"}`

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	// Pull data._service.sdl out of the JSON envelope and assert it's a
	// non-empty string containing the customer's `type User` definition (so we
	// know it's the customer's SDL — not an empty stub or some default).
	sdl, dataType, _, err := jsonparser.Get(resBody, "data", "_service", "sdl")
	require.NoError(t, err, "response missing data._service.sdl: %s", string(resBody))
	require.Equal(t, jsonparser.String, dataType, "data._service.sdl must be a string: %s", string(resBody))
	sdlStr := string(sdl)
	require.NotEmpty(t, sdlStr, "data._service.sdl must be non-empty")
	require.Contains(t, sdlStr, "type User", "_service.sdl must contain the customer's `type User` definition; got: %s", sdlStr)
	require.Contains(t, sdlStr, `@key(fields: \"id\")`, "_service.sdl must preserve the @key directive; got: %s", sdlStr)
}

// TestGraphQLMiddleware_UDGFederation_ServiceQueryEmitsFederationV2Link
// regression-tests the bug where Tyk emitted the customer's SDL verbatim from
// `_service { sdl }`, lacking any `@link` directive. Apollo Rover and Apollo
// Router classify a subgraph that has `@key` but no federation `@link` as
// federation v1 and reject it under the default v2 composition pipeline. The
// fix auto-prepends `@link(url: "https://specs.apollo.dev/federation/v2.5",
// import: [...])` to the SDL when the customer's schema is federation-shaped
// (has `@key`) but version-less.
func TestGraphQLMiddleware_UDGFederation_ServiceQueryEmitsFederationV2Link(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	customerSchema := `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = customerSchema
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindREST,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{
						Type:   "User",
						Fields: []string{"id", "username"},
					},
				},
				Config: []byte(fmt.Sprintf(`{
						"url": "%s/users/{{ .object.id }}",
						"method": "GET"
					}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	body := `{"query": "{ _service { sdl } }"}`

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	sdl, dataType, _, err := jsonparser.Get(resBody, "data", "_service", "sdl")
	require.NoError(t, err, "response missing data._service.sdl: %s", string(resBody))
	require.Equal(t, jsonparser.String, dataType, "data._service.sdl must be a string: %s", string(resBody))
	sdlStr := string(sdl)
	require.Contains(t, sdlStr, `type User @key(fields: \"id\")`, "_service.sdl must preserve the customer's @key type; got: %s", sdlStr)
	require.Contains(t, sdlStr, `@link(url:`, "_service.sdl must include an @link directive so Apollo recognises Tyk as federation v2; got: %s", sdlStr)
	require.Contains(t, sdlStr, `apollo.dev/federation/v2`, "_service.sdl @link must reference federation/v2; got: %s", sdlStr)
}

// TestGraphQLMiddleware_UDGFederation_OrphanQueryFieldNotInService
// regression-tests bug #3: Apollo Router proxying e.g.
// `{ user(id:"1") { id username } }` to Tyk returned
// `Failed to fetch from Subgraph at path 'query.user'`. The customer SDL
// declares `Query.user(id: ID!): User` but no UDG data source is registered
// for that field — only the `User` entity's fields. The supergraph
// composition would still route any query against `Query.user` to Tyk and
// fail. The fix strips orphan Query fields (those not backed by any data
// source) from the SDL emitted by `_service { sdl }`, while leaving the
// schema used for validation/planning untouched so direct `_entities`
// resolution continues to work.
func TestGraphQLMiddleware_UDGFederation_OrphanQueryFieldNotInService(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/1" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id": "1", "username": "alice"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	// Same fixture as TestGraphQLMiddleware_UDGFederation: customer declares
	// Query.user(id) but registers no Query data source — only the User
	// entity's REST resolver. user(id) is therefore an orphan Query field.
	customerSchema := `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = customerSchema
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindREST,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{Type: "User", Fields: []string{"id", "username"}},
				},
				Config: []byte(fmt.Sprintf(`{
						"url": "%s/users/{{ .object.id }}",
						"method": "GET"
					}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	// 1) `_service { sdl }` must NOT advertise the orphan Query field.
	body := `{"query": "{ _service { sdl } }"}`
	res, err := g.Run(t, test.TestCase{Method: "POST", Path: "/", Data: body, Code: http.StatusOK})
	require.NoError(t, err)
	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	sdl, dataType, _, err := jsonparser.Get(resBody, "data", "_service", "sdl")
	require.NoError(t, err, "response missing data._service.sdl: %s", string(resBody))
	require.Equal(t, jsonparser.String, dataType, "data._service.sdl must be a string: %s", string(resBody))
	sdlStr := string(sdl)
	require.NotContains(t, sdlStr, "user(id:", "orphan Query.user must be stripped from advertised SDL; got: %s", sdlStr)
	require.Contains(t, sdlStr, `type User @key(fields: \"id\")`, "User entity must remain in the SDL; got: %s", sdlStr)

	// 2) `_entities` resolution against User still works — the customer's
	// actual schema (used for validation/planning) is untouched.
	entitiesQuery := `query($representations: [_Any!]!) { _entities(representations: $representations) { ... on User { id username } } }`
	variables := `{"representations": [{"__typename": "User", "id": "1"}]}`
	body2 := fmt.Sprintf(`{"query": %q, "variables": %s}`, entitiesQuery, variables)
	res2, err := g.Run(t, test.TestCase{Method: "POST", Path: "/", Data: body2, Code: http.StatusOK})
	require.NoError(t, err)
	res2Body, err := io.ReadAll(res2.Body)
	require.NoError(t, err)
	res2.Body.Close()
	require.Contains(t, string(res2Body), `"id":"1"`, "_entities lookup must still resolve; got: %s", string(res2Body))
	require.Contains(t, string(res2Body), `"username":"alice"`, "_entities lookup must still resolve; got: %s", string(res2Body))
}

// TestGraphQLMiddleware_UDGFederation_PartialFailure verifies the Apollo
// Federation contract for `_entities(representations: [_Any!]!): [_Entity]!`:
// when one representation fails to resolve (here, a 404 from the upstream),
// that index should come back as `null` while the other entities resolve
// successfully, accompanied by a top-level GraphQL error pointing at the
// failed index. The test hits a real httptest server — no transport mocks.
func TestGraphQLMiddleware_UDGFederation_PartialFailure(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id": "1", "username": "alice"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindREST,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{
						Type:   "User",
						Fields: []string{"id", "username"},
					},
				},
				Config: []byte(fmt.Sprintf(`{
						"url": "%s/users/{{ .object.id }}",
						"method": "GET"
					}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	query := `
			query($representations: [_Any!]!) {
				_entities(representations: $representations) {
					... on User {
						id
						username
					}
				}
			}
		`
	variables := `{"representations": [{"__typename": "User", "id": "1"}, {"__typename": "User", "id": "2"}]}`

	body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	var parsed struct {
		Data struct {
			Entities []map[string]any `json:"_entities"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
			Path    []any  `json:"path"`
		} `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(resBody, &parsed), "response: %s", string(resBody))

	require.Len(t, parsed.Data.Entities, 2, "response: %s", string(resBody))
	// First entity: resolved successfully.
	require.NotNil(t, parsed.Data.Entities[0], "response: %s", string(resBody))
	require.Equal(t, "1", parsed.Data.Entities[0]["id"])
	require.Equal(t, "alice", parsed.Data.Entities[0]["username"])
	// Second entity: 404 upstream — must be null.
	require.Nil(t, parsed.Data.Entities[1], "response: %s", string(resBody))

	// A top-level error must reference index 1 of `_entities`. The path
	// elements are decoded into `any` (string for "_entities", float64 for
	// the index because encoding/json decodes JSON numbers as float64).
	require.NotEmpty(t, parsed.Errors, "expected an error for the failed entity, got: %s", string(resBody))
	foundIndexOneErr := false
	for _, e := range parsed.Errors {
		if len(e.Path) >= 2 {
			first, _ := e.Path[0].(string)
			second, _ := e.Path[1].(float64)
			if first == "_entities" && int(second) == 1 {
				require.NotEmpty(t, e.Message, "error at _entities[1] should have a message: %s", string(resBody))
				foundIndexOneErr = true
				break
			}
		}
	}
	require.True(t, foundIndexOneErr, "expected an error with path [\"_entities\", 1] in: %s", string(resBody))
}

// TestGraphQLMiddleware_UDGFederation_RESTUpstreamReturnsNull regression-tests
// the nil-map panic path: a REST upstream answering with a JSON `null` body
// used to crash with "assignment to entry in nil map" when the resolver tried
// to set `__typename` on the (nil) entity. The fix surfaces the situation as a
// per-entity resolution error instead.
func TestGraphQLMiddleware_UDGFederation_RESTUpstreamReturnsNull(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Valid JSON, but `null` decodes to a nil map[string]any.
		_, _ = w.Write([]byte(`null`))
	}))
	defer mockServer.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindREST,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{Type: "User", Fields: []string{"id", "username"}},
				},
				Config: []byte(fmt.Sprintf(`{
						"url": "%s/users/{{ .object.id }}",
						"method": "GET"
					}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	query := `
			query($representations: [_Any!]!) {
				_entities(representations: $representations) {
					... on User { id username }
				}
			}
		`
	variables := `{"representations": [{"__typename": "User", "id": "1"}]}`
	body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)
	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	// We must get a normal 200 with `_entities[0]` null and a top-level error,
	// not a 500 from the recovered panic.
	var parsed struct {
		Data struct {
			Entities []map[string]any `json:"_entities"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
			Path    []any  `json:"path"`
		} `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(resBody, &parsed), "response: %s", string(resBody))
	require.Len(t, parsed.Data.Entities, 1)
	require.Nil(t, parsed.Data.Entities[0], "response: %s", string(resBody))
	require.NotEmpty(t, parsed.Errors, "expected a per-entity error, got: %s", string(resBody))
}

// TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_Federation exercises the
// federation pass-through strategy: the upstream is a federation subgraph that
// answers `query { _service { sdl } }`, so Tyk forwards an
// `_entities(representations: ...)` query verbatim and unwraps `data._entities[0]`.
func TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_Federation(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	// The upstream advertises this SDL on `_service { sdl }` — the actual
	// content doesn't matter for routing decisions, only that it is a
	// non-empty string.
	upstreamSDL := `type User @key(fields: "id") { id: ID! username: String! }`

	type gqlReq struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req gqlReq
		require.NoError(t, json.Unmarshal(bodyBytes, &req))

		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(req.Query, "_service"):
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"_service":{"sdl":%q}}}`, upstreamSDL)))
		case strings.Contains(req.Query, "_entities"):
			// Read the single representation we forwarded and echo it back as
			// a fully resolved User.
			repsRaw, ok := req.Variables["r"]
			require.True(t, ok, "expected variable 'r' in entities forward, got: %s", string(bodyBytes))
			reps, ok := repsRaw.([]any)
			require.True(t, ok)
			require.Len(t, reps, 1)
			rep, ok := reps[0].(map[string]any)
			require.True(t, ok)
			id, _ := rep["id"].(string)

			// Return the entity at _entities[0].
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"data":{"_entities":[{"__typename":"User","id":%q,"username":"alice"}]}}`,
				id,
			)))
		default:
			t.Errorf("unexpected upstream query: %s", req.Query)
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	defer mockServer.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{
						Type:   "User",
						Fields: []string{"id", "username"},
					},
				},
				Config: []byte(fmt.Sprintf(`{
						"url": %q,
						"method": "POST"
					}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	query := `
			query($representations: [_Any!]!) {
				_entities(representations: $representations) {
					... on User {
						id
						username
					}
				}
			}
		`
	variables := `{"representations": [{"__typename": "User", "id": "1"}]}`

	body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	require.Contains(t, string(resBody), `"id":"1"`, "response: %s", string(resBody))
	require.Contains(t, string(resBody), `"username":"alice"`, "response: %s", string(resBody))
}

// TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_Hasura exercises the
// generated-lookup strategy: the upstream is a non-federation GraphQL server
// (Hasura/PostGraphile-style). It does NOT answer `_service { sdl }` but does
// support introspection and exposes `user(id: ID!): User`. Tyk auto-discovers
// that field and uses it for entity resolution.
func TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_Hasura(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	type gqlReq struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}

	// Minimal introspection response satisfying the resolver's probe: a Query
	// type with a single `user(id: ID!): User` field. The shape (kind/name/
	// ofType) mirrors what __schema returns from a real upstream.
	const introspectionResponse = `{
		"data": {
			"__schema": {
				"queryType": {"name": "Query"},
				"types": [
					{
						"kind": "OBJECT",
						"name": "Query",
						"fields": [
							{
								"name": "user",
								"type": {"kind": "OBJECT", "name": "User", "ofType": null},
								"args": [
									{
										"name": "id",
										"type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}}
									}
								]
							}
						]
					},
					{
						"kind": "OBJECT",
						"name": "User",
						"fields": [
							{"name": "id", "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}}, "args": []},
							{"name": "username", "type": {"kind": "SCALAR", "name": "String", "ofType": null}, "args": []}
						]
					}
				]
			}
		}
	}`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req gqlReq
		require.NoError(t, json.Unmarshal(bodyBytes, &req))

		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(req.Query, "_service"):
			// Hasura-style: doesn't know about federation. Standard GraphQL
			// validation error (still HTTP 200, errors in body).
			_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"_service\" on type \"Query\"."}]}`))
		case strings.Contains(req.Query, "__schema"):
			_, _ = w.Write([]byte(introspectionResponse))
		case strings.Contains(req.Query, "user("):
			// The generated lookup query renders as
			//   query($k: ID!) { user(id: $k) { __typename id username } }
			// Verify the variable shape and respond.
			kRaw, ok := req.Variables["k"]
			require.True(t, ok, "expected variable 'k' in lookup query, got: %s", string(bodyBytes))
			id, _ := kRaw.(string)
			require.NotEmpty(t, id)
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"data":{"user":{"__typename":"User","id":%q,"username":"alice"}}}`,
				id,
			)))
		default:
			t.Errorf("unexpected upstream query: %s", req.Query)
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	defer mockServer.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{
						Type:   "User",
						Fields: []string{"id", "username"},
					},
				},
				Config: []byte(fmt.Sprintf(`{
						"url": %q,
						"method": "POST"
					}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	query := `
			query($representations: [_Any!]!) {
				_entities(representations: $representations) {
					... on User {
						id
						username
					}
				}
			}
		`
	variables := `{"representations": [{"__typename": "User", "id": "1"}]}`

	body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	require.Contains(t, string(resBody), `"id":"1"`, "response: %s", string(resBody))
	require.Contains(t, string(resBody), `"username":"alice"`, "response: %s", string(resBody))
}

// TestGraphQLMiddleware_UDGFederation_CompositeKey_Rejected verifies that an
// entity with a composite @key (e.g. `@key(fields: "id sku")`) backed by a
// GraphQL data source surfaces a clear error at adapter-load time naming the
// entity type and the composite-key limitation. The auto-detect path doesn't
// know which arg shape to introspect for and we'd rather refuse than silently
// pick one — customers can opt into a custom operation via has_operation.
func TestGraphQLMiddleware_UDGFederation_CompositeKey_Rejected(t *testing.T) {
	// The upstream is never hit — composite-key rejection happens before any
	// network probe — but we keep a real server so the data-source URL is
	// realistic.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream should not be hit for composite-key rejection; got %s %s", r.Method, r.URL.Path)
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Enabled:       true,
			Version:       apidef.GraphQLConfigVersion3Preview,
			ExecutionMode: apidef.GraphQLExecutionModeExecutionEngine,
			Schema: `
				type Product @key(fields: "id sku") {
					id: ID!
					sku: String!
					name: String!
				}
				type Query {
					product(id: ID!): Product
				}
			`,
			Engine: apidef.GraphQLEngineConfig{
				DataSources: []apidef.GraphQLEngineDataSource{
					{
						Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
						Name: "product_ds",
						RootFields: []apidef.GraphQLTypeFields{
							{Type: "Product", Fields: []string{"id", "sku", "name"}},
						},
						Config: []byte(fmt.Sprintf(`{"url": %q, "method": "POST"}`, mockServer.URL)),
					},
				},
			},
		},
	}

	udg := &enginev3.UniversalDataGraph{ApiDefinition: apiDef}

	_, err := udg.EngineConfigV3()
	require.Error(t, err, "expected composite-key rejection at engine config build time")
	msg := err.Error()
	require.Contains(t, msg, "Product", "error must name the offending entity type, got: %s", msg)
	require.Contains(t, msg, "composite", "error must mention the composite-key limitation, got: %s", msg)
}

// TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_UpstreamGraphQLError
// verifies that a Hasura-style upstream returning a valid HTTP 200 with a
// `{"data":..., "errors":[...]}` body produces the expected partial-failure
// behaviour: Tyk's `_entities[i]` is null for the failed representation while
// successful representations resolve normally, and a top-level error surfaces
// the upstream message.
func TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_UpstreamGraphQLError(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	type gqlReq struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}

	const introspectionResponse = `{
		"data": {
			"__schema": {
				"queryType": {"name": "Query"},
				"types": [
					{
						"kind": "OBJECT",
						"name": "Query",
						"fields": [
							{
								"name": "user",
								"type": {"kind": "OBJECT", "name": "User", "ofType": null},
								"args": [
									{
										"name": "id",
										"type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}}
									}
								]
							}
						]
					}
				]
			}
		}
	}`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req gqlReq
		require.NoError(t, json.Unmarshal(bodyBytes, &req))

		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(req.Query, "_service"):
			// Not a federation subgraph.
			_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"_service\" on type \"Query\"."}]}`))
		case strings.Contains(req.Query, "__schema"):
			_, _ = w.Write([]byte(introspectionResponse))
		case strings.Contains(req.Query, "user("):
			id, _ := req.Variables["k"].(string)
			require.NotEmpty(t, id)
			if id == "1" {
				_, _ = w.Write([]byte(`{"data":{"user":{"__typename":"User","id":"1","username":"alice"}}}`))
				return
			}
			// Hasura-style: 200 OK with errors body.
			_, _ = w.Write([]byte(`{"data":{"user":null},"errors":[{"message":"User not found"}]}`))
		default:
			t.Errorf("unexpected upstream query: %s", req.Query)
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	defer mockServer.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{Type: "User", Fields: []string{"id", "username"}},
				},
				Config: []byte(fmt.Sprintf(`{"url": %q, "method": "POST"}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	query := `
			query($representations: [_Any!]!) {
				_entities(representations: $representations) {
					... on User {
						id
						username
					}
				}
			}
		`
	variables := `{"representations": [{"__typename": "User", "id": "1"}, {"__typename": "User", "id": "2"}]}`
	body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	var parsed struct {
		Data struct {
			Entities []map[string]any `json:"_entities"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
			Path    []any  `json:"path"`
		} `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(resBody, &parsed), "response: %s", string(resBody))

	require.Len(t, parsed.Data.Entities, 2, "response: %s", string(resBody))
	require.NotNil(t, parsed.Data.Entities[0], "response: %s", string(resBody))
	require.Equal(t, "1", parsed.Data.Entities[0]["id"])
	require.Equal(t, "alice", parsed.Data.Entities[0]["username"])
	require.Nil(t, parsed.Data.Entities[1], "response: %s", string(resBody))

	require.NotEmpty(t, parsed.Errors, "expected an error wrapping the upstream gql error: %s", string(resBody))
	foundUserNotFound := false
	for _, e := range parsed.Errors {
		if strings.Contains(e.Message, "User not found") {
			foundUserNotFound = true
			break
		}
	}
	require.True(t, foundUserNotFound, "expected an error referencing the upstream message, got: %s", string(resBody))
}

// TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_NoLookupField verifies
// that a non-federation upstream whose Query type has no field returning the
// entity type fails the engine config build with a documented hint to set
// has_operation=true.
func TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_NoLookupField(t *testing.T) {
	type gqlReq struct {
		Query string `json:"query"`
	}

	// Introspection response that has a Query but with no field returning User.
	const introspectionResponse = `{
		"data": {
			"__schema": {
				"queryType": {"name": "Query"},
				"types": [
					{
						"kind": "OBJECT",
						"name": "Query",
						"fields": [
							{
								"name": "ping",
								"type": {"kind": "SCALAR", "name": "String", "ofType": null},
								"args": []
							}
						]
					}
				]
			}
		}
	}`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req gqlReq
		require.NoError(t, json.Unmarshal(bodyBytes, &req))

		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(req.Query, "_service"):
			_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"_service\" on type \"Query\"."}]}`))
		case strings.Contains(req.Query, "__schema"):
			_, _ = w.Write([]byte(introspectionResponse))
		default:
			t.Errorf("unexpected upstream query: %s", req.Query)
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	defer mockServer.Close()

	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Enabled:       true,
			Version:       apidef.GraphQLConfigVersion3Preview,
			ExecutionMode: apidef.GraphQLExecutionModeExecutionEngine,
			Schema: `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`,
			Engine: apidef.GraphQLEngineConfig{
				DataSources: []apidef.GraphQLEngineDataSource{
					{
						Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
						Name: "user_ds",
						RootFields: []apidef.GraphQLTypeFields{
							{Type: "User", Fields: []string{"id", "username"}},
						},
						Config: []byte(fmt.Sprintf(`{"url": %q, "method": "POST"}`, mockServer.URL)),
					},
				},
			},
		},
	}

	udg := &enginev3.UniversalDataGraph{ApiDefinition: apiDef}
	_, err := udg.EngineConfigV3()
	require.Error(t, err, "expected engine config build to fail when no lookup field exists for the entity")
	msg := err.Error()
	require.Contains(t, msg, "User", "error must name the entity type, got: %s", msg)
	require.Contains(t, msg, "no Query field", "error must explain the missing lookup, got: %s", msg)
	require.Contains(t, msg, "has_operation", "error must hint at the has_operation override, got: %s", msg)
}

// TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_AmbiguousLookupField
// covers two cases of ambiguous auto-detect: 4a — two Query fields return the
// entity type but exactly one's arg name matches the @key field, so we pick
// it; 4b — neither candidate's arg matches the @key field, so we refuse and
// surface a documented error.
func TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_AmbiguousLookupField(t *testing.T) {
	type gqlReq struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}

	// Helper that builds an introspection blob with two candidate fields. The
	// first candidate uses `arg1Name`, the second uses `arg2Name`. Both return
	// the User type.
	introspectionFor := func(arg1Name, arg2Name string) string {
		return fmt.Sprintf(`{
			"data": {
				"__schema": {
					"queryType": {"name": "Query"},
					"types": [
						{
							"kind": "OBJECT",
							"name": "Query",
							"fields": [
								{
									"name": "userPrimary",
									"type": {"kind": "OBJECT", "name": "User", "ofType": null},
									"args": [
										{
											"name": %q,
											"type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}}
										}
									]
								},
								{
									"name": "userSecondary",
									"type": {"kind": "OBJECT", "name": "User", "ofType": null},
									"args": [
										{
											"name": %q,
											"type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "String", "ofType": null}}
										}
									]
								}
							]
						}
					]
				}
			}
		}`, arg1Name, arg2Name)
	}

	buildAPIDef := func(serverURL string) *apidef.APIDefinition {
		return &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Enabled:       true,
				Version:       apidef.GraphQLConfigVersion3Preview,
				ExecutionMode: apidef.GraphQLExecutionModeExecutionEngine,
				Schema: `
					type User @key(fields: "id") {
						id: ID!
						username: String!
					}
					type Query {
						user(id: ID!): User
					}
				`,
				Engine: apidef.GraphQLEngineConfig{
					DataSources: []apidef.GraphQLEngineDataSource{
						{
							Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
							Name: "user_ds",
							RootFields: []apidef.GraphQLTypeFields{
								{Type: "User", Fields: []string{"id", "username"}},
							},
							Config: []byte(fmt.Sprintf(`{"url": %q, "method": "POST"}`, serverURL)),
						},
					},
				},
			},
		}
	}

	t.Run("PrefersCandidateMatchingKeyArg", func(t *testing.T) {
		g := StartTest(nil)
		defer g.Close()

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req gqlReq
			require.NoError(t, json.Unmarshal(bodyBytes, &req))

			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.Contains(req.Query, "_service"):
				_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"_service\" on type \"Query\"."}]}`))
			case strings.Contains(req.Query, "__schema"):
				_, _ = w.Write([]byte(introspectionFor("id", "email")))
			case strings.Contains(req.Query, "userPrimary("):
				// Auto-pick must select userPrimary because its arg is `id`.
				id, _ := req.Variables["k"].(string)
				require.NotEmpty(t, id)
				_, _ = w.Write([]byte(fmt.Sprintf(
					`{"data":{"userPrimary":{"__typename":"User","id":%q,"username":"alice"}}}`, id,
				)))
			case strings.Contains(req.Query, "userSecondary("):
				t.Errorf("auto-pick incorrectly chose userSecondary; expected userPrimary because @key field is 'id'")
				http.Error(w, "wrong field", http.StatusBadRequest)
			default:
				t.Errorf("unexpected upstream query: %s", req.Query)
				http.Error(w, "unexpected query", http.StatusBadRequest)
			}
		}))
		defer mockServer.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
			spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
			spec.GraphQL.Schema = `
					type User @key(fields: "id") {
						id: ID!
						username: String!
					}
					type Query {
						user(id: ID!): User
					}
				`
			spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
				{
					Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
					Name: "user_ds",
					RootFields: []apidef.GraphQLTypeFields{
						{Type: "User", Fields: []string{"id", "username"}},
					},
					Config: []byte(fmt.Sprintf(`{"url": %q, "method": "POST"}`, mockServer.URL)),
				},
			}
		})[0]
		g.Gw.LoadAPI(spec)

		query := `
			query($representations: [_Any!]!) {
				_entities(representations: $representations) {
					... on User {
						id
						username
					}
				}
			}
		`
		variables := `{"representations": [{"__typename": "User", "id": "1"}]}`
		body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

		res, err := g.Run(t, test.TestCase{
			Method: "POST",
			Path:   "/",
			Data:   body,
			Code:   http.StatusOK,
		})
		require.NoError(t, err)

		resBody, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		res.Body.Close()

		require.Contains(t, string(resBody), `"id":"1"`, "response: %s", string(resBody))
		require.Contains(t, string(resBody), `"username":"alice"`, "response: %s", string(resBody))
	})

	t.Run("FailsWhenNoCandidateMatchesKeyArg", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req gqlReq
			require.NoError(t, json.Unmarshal(bodyBytes, &req))

			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.Contains(req.Query, "_service"):
				_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"_service\" on type \"Query\"."}]}`))
			case strings.Contains(req.Query, "__schema"):
				_, _ = w.Write([]byte(introspectionFor("uid", "email")))
			default:
				t.Errorf("unexpected upstream query during ambiguity probe: %s", req.Query)
				http.Error(w, "unexpected query", http.StatusBadRequest)
			}
		}))
		defer mockServer.Close()

		udg := &enginev3.UniversalDataGraph{ApiDefinition: buildAPIDef(mockServer.URL)}
		_, err := udg.EngineConfigV3()
		require.Error(t, err, "expected ambiguous-lookup rejection at engine config build time")
		msg := err.Error()
		require.Contains(t, msg, "User", "error must name the entity, got: %s", msg)
		require.Contains(t, msg, "ambiguous", "error must mention ambiguity, got: %s", msg)
		require.Contains(t, msg, "has_operation", "error must hint at has_operation override, got: %s", msg)
	})
}

// TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_HeadersForwarded ensures
// that headers configured on a GraphQL data source are propagated on the
// _entities-equivalent request issued by the resolver. The mock returns 403
// when the expected header is missing or wrong.
func TestGraphQLMiddleware_UDGFederation_GraphQLUpstream_HeadersForwarded(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	const expectedAuth = "Bearer abc"
	upstreamSDL := `type User @key(fields: "id") { id: ID! username: String! }`

	type gqlReq struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Auth") != expectedAuth {
			http.Error(w, "missing or wrong X-Test-Auth header", http.StatusForbidden)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req gqlReq
		require.NoError(t, json.Unmarshal(bodyBytes, &req))

		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "_service"):
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"_service":{"sdl":%q}}}`, upstreamSDL)))
		case strings.Contains(req.Query, "_entities"):
			repsRaw, _ := req.Variables["r"].([]any)
			require.Len(t, repsRaw, 1)
			rep, _ := repsRaw[0].(map[string]any)
			id, _ := rep["id"].(string)
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"data":{"_entities":[{"__typename":"User","id":%q,"username":"alice"}]}}`,
				id,
			)))
		default:
			t.Errorf("unexpected upstream query: %s", req.Query)
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	defer mockServer.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{Type: "User", Fields: []string{"id", "username"}},
				},
				Config: []byte(fmt.Sprintf(
					`{"url": %q, "method": "POST", "headers": {"X-Test-Auth": "Bearer abc"}}`,
					mockServer.URL,
				)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	query := `
			query($representations: [_Any!]!) {
				_entities(representations: $representations) {
					... on User {
						id
						username
					}
				}
			}
		`
	variables := `{"representations": [{"__typename": "User", "id": "1"}]}`
	body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	require.Contains(t, string(resBody), `"id":"1"`, "response: %s", string(resBody))
	require.Contains(t, string(resBody), `"username":"alice"`, "response: %s", string(resBody))
	require.NotContains(t, string(resBody), "missing or wrong X-Test-Auth", "response: %s", string(resBody))
}

// TestGraphQLMiddleware_UDGFederation_OperationOverride_Works verifies the
// has_operation=true path: a customer-supplied query template is used verbatim
// (after rendering), and probes are skipped — the upstream is plain GraphQL
// that doesn't know about federation or even introspection.
func TestGraphQLMiddleware_UDGFederation_OperationOverride_Works(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	type gqlReq struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req gqlReq
		require.NoError(t, json.Unmarshal(bodyBytes, &req))

		// In operation-override mode the resolver must NOT issue probes.
		if strings.Contains(req.Query, "_service") || strings.Contains(req.Query, "__schema") {
			t.Errorf("operation override must skip probes; got query: %s", req.Query)
			http.Error(w, "unexpected probe", http.StatusBadRequest)
			return
		}

		require.Contains(t, req.Query, "findUserById", "expected the customer-supplied operation; got: %s", req.Query)
		id, _ := req.Variables["id"].(string)
		require.NotEmpty(t, id, "expected variables.id to be rendered from .object.id; got: %v", req.Variables)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(
			`{"data":{"findUserById":{"id":%q,"username":"alice"}}}`, id,
		)))
	}))
	defer mockServer.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
				Name: "user_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{Type: "User", Fields: []string{"id", "username"}},
				},
				Config: []byte(fmt.Sprintf(`{
					"url": %q,
					"method": "POST",
					"has_operation": true,
					"operation": "query($id: ID!) { findUserById(id: $id) { id username } }",
					"variables": {"id":"{{.object.id}}"}
				}`, mockServer.URL)),
			},
		}
	})[0]

	g.Gw.LoadAPI(spec)

	query := `
			query($representations: [_Any!]!) {
				_entities(representations: $representations) {
					... on User {
						id
						username
					}
				}
			}
		`
	variables := `{"representations": [{"__typename": "User", "id": "1"}]}`
	body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	require.Contains(t, string(resBody), `"id":"1"`, "response: %s", string(resBody))
	require.Contains(t, string(resBody), `"username":"alice"`, "response: %s", string(resBody))
}

// TestGraphQLMiddleware_UDGFederation_OperationOverride_MalformedTemplate
// verifies that a syntactically broken operation template surfaces a clear
// error at engine config build time naming the entity type.
func TestGraphQLMiddleware_UDGFederation_OperationOverride_MalformedTemplate(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit when template parsing fails; got %s %s", r.Method, r.URL.Path)
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Enabled:       true,
			Version:       apidef.GraphQLConfigVersion3Preview,
			ExecutionMode: apidef.GraphQLExecutionModeExecutionEngine,
			Schema: `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`,
			Engine: apidef.GraphQLEngineConfig{
				DataSources: []apidef.GraphQLEngineDataSource{
					{
						Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
						Name: "user_ds",
						RootFields: []apidef.GraphQLTypeFields{
							{Type: "User", Fields: []string{"id", "username"}},
						},
						// `{{.object.}}` is a syntactically invalid Go template
						// — a trailing dot with no field name fails parsing.
						Config: []byte(fmt.Sprintf(`{
							"url": %q,
							"method": "POST",
							"has_operation": true,
							"operation": "query { x({{.object.}}) }",
							"variables": "{}"
						}`, mockServer.URL)),
					},
				},
			},
		},
	}

	udg := &enginev3.UniversalDataGraph{ApiDefinition: apiDef}
	_, err := udg.EngineConfigV3()
	require.Error(t, err, "expected malformed operation template to fail engine config build")
	msg := err.Error()
	require.Contains(t, msg, "User", "error must reference the entity type / data source, got: %s", msg)
	require.Contains(t, msg, "operation template", "error must mention the operation template parse failure, got: %s", msg)
}

// TestGraphQLMiddleware_ProxyMode_FederationPassthrough_AugmentsSchema verifies
// the Apollo Federation v2 proxy-mode flow: when the customer's SDL declares a
// `@key`-decorated type, Tyk auto-augments its schema with the federation
// extensions so `_entities` queries pass validation and forward verbatim to
// an upstream subgraph or Apollo Router. Tyk does not resolve `_entities`
// itself in proxy mode — the upstream owns the response shape.
func TestGraphQLMiddleware_ProxyMode_FederationPassthrough_AugmentsSchema(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	var receivedQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.Unmarshal(body, &req)
		receivedQuery = req.Query
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"_entities":[{"__typename":"User","id":"1","username":"alice"}]}}`))
	}))
	defer upstream.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
	})[0]

	g.Gw.LoadAPI(spec)

	query := `query($representations: [_Any!]!) {
		_entities(representations: $representations) {
			... on User { id username }
		}
	}`
	variables := `{"representations": [{"__typename": "User", "id": "1"}]}`
	body := fmt.Sprintf(`{"query": %q, "variables": %s}`, query, variables)

	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	// Tyk must NOT reject the `_entities` query at validation. The upstream
	// must have received the query, and its response must flow back unchanged.
	require.Contains(t, receivedQuery, "_entities", "upstream did not receive the _entities query: %s", string(resBody))
	require.Contains(t, string(resBody), `"id":"1"`)
	require.Contains(t, string(resBody), `"username":"alice"`)
	require.NotContains(t, string(resBody), `not defined on Query`, "schema validation should not reject _entities; got: %s", string(resBody))
}

// TestGraphQLMiddleware_ProxyMode_FederationPassthrough_Service verifies that
// `_service { sdl }` passes validation in proxy mode (it's a normal field on
// Query after augmentation) and that the upstream subgraph's response is
// returned verbatim.
func TestGraphQLMiddleware_ProxyMode_FederationPassthrough_Service(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	const upstreamSDL = `type User @key(fields: "id") { id: ID! username: String! }`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"_service":{"sdl":%q}}}`, upstreamSDL)))
	}))
	defer upstream.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = `
				type User @key(fields: "id") {
					id: ID!
					username: String!
				}
				type Query {
					user(id: ID!): User
				}
			`
	})[0]

	g.Gw.LoadAPI(spec)

	body := `{"query":"{ _service { sdl } }"}`
	res, err := g.Run(t, test.TestCase{
		Method: "POST",
		Path:   "/",
		Data:   body,
		Code:   http.StatusOK,
	})
	require.NoError(t, err)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()

	require.Contains(t, string(resBody), `"_service"`, "expected _service in response, got: %s", string(resBody))
	require.Contains(t, string(resBody), `"sdl"`)
	require.NotContains(t, string(resBody), `not defined on Query`, "schema validation should not reject _service; got: %s", string(resBody))
}

// TestGraphQLMiddleware_ProxyMode_FederationPassthrough_NoKeyDirectiveSkipsAugment
// verifies the negative case: a plain GraphQL schema without any `@key`
// directive must NOT have the federation extensions injected. Sending a
// query for `_entities` against such a schema should fail validation inside
// Tyk before the request can reach the upstream.
func TestGraphQLMiddleware_ProxyMode_FederationPassthrough_NoKeyDirectiveSkipsAugment(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"hello":"world"}}`))
	}))
	defer upstream.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		// No `@key` directive anywhere — plain GraphQL.
		spec.GraphQL.Schema = `
				type User {
					id: ID!
					username: String!
				}
				type Query {
					hello: String
					user(id: ID!): User
				}
			`
	})[0]

	g.Gw.LoadAPI(spec)

	// `_entities` must NOT be available on this schema. The query should be
	// rejected at validation; the upstream must not be hit.
	entitiesBody := `{"query":"query($r: [_Any!]!) { _entities(representations: $r) { ... on User { id } } }","variables":{"r":[{"__typename":"User","id":"1"}]}}`
	res, err := g.Run(t, test.TestCase{
		Method:    "POST",
		Path:      "/",
		Data:      entitiesBody,
		BodyMatch: `_entities`,
		Code:      http.StatusBadRequest,
	})
	require.NoError(t, err)
	res.Body.Close()
	require.False(t, upstreamHit, "upstream must not be hit when _entities fails validation")

	// Sanity check: a regular query for `hello` does pass through and reach
	// the upstream — proving the proxy mode itself works for this schema.
	upstreamHit = false
	helloBody := `{"query":"{ hello }"}`
	res, err = g.Run(t, test.TestCase{
		Method:    "POST",
		Path:      "/",
		Data:      helloBody,
		Code:      http.StatusOK,
		BodyMatch: `"hello":"world"`,
	})
	require.NoError(t, err)
	res.Body.Close()
	require.True(t, upstreamHit, "upstream should be hit for a valid query")
}

// TestGraphQLMiddleware_V2WithKeyDirective_LogsWarning regression-tests
// fix #2: a customer using GraphQL config version 2 with `@key`-decorated
// types previously got no signal that federation features (`_entities`,
// `_service`, schema augmentation) only run under version 3. The fix emits
// a warning during middleware Init pointing at version 3 (Preview).
//
// We attach a logrus hook to the package-level gateway logger before Init
// runs, build a V2 GraphQL spec with `@key`, drive the middleware through
// LoadAPI, and then assert the warning was captured. The hook is removed
// in t.Cleanup to keep test isolation.
func TestGraphQLMiddleware_V2WithKeyDirective_LogsWarning(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	// `go test` without TYK_LOGLEVEL clamps the gateway logger to ErrorLevel
	// (see gateway/server.go), which would suppress our Warn. Lift it for
	// the duration of this test so the warning is observable.
	prevLevel := log.GetLevel()
	log.SetLevel(logrus.WarnLevel)
	t.Cleanup(func() { log.SetLevel(prevLevel) })

	hook := &logrustest.Hook{}
	log.AddHook(hook)
	t.Cleanup(func() {
		// logrus.Logger has no public RemoveHook, so swap out hooks for a
		// fresh map that omits the test hook. Other concurrent tests can
		// still log; we just stop capturing.
		newHooks := logrus.LevelHooks{}
		for _, hooksAtLevel := range log.Hooks {
			for _, h := range hooksAtLevel {
				if h == hook {
					continue
				}
				newHooks.Add(h)
			}
		}
		log.ReplaceHooks(newHooks)
	})

	customerSchema := `
		type User @key(fields: "id") {
			id: ID!
			username: String!
		}
		type Query {
			user(id: ID!): User
		}
	`

	const apiID = "v2-with-key-warn-api"
	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
		spec.GraphQL.Version = apidef.GraphQLConfigVersion2
		spec.GraphQL.Schema = customerSchema
	})[0]
	g.Gw.LoadAPI(spec)

	var found *logrus.Entry
	for i := range hook.AllEntries() {
		entry := hook.AllEntries()[i]
		if entry.Level != logrus.WarnLevel {
			continue
		}
		if !strings.Contains(entry.Message, apiID) {
			continue
		}
		if !strings.Contains(entry.Message, "version 3") {
			continue
		}
		found = entry
		break
	}
	if found == nil {
		// Provide useful diagnostics on failure.
		var msgs []string
		for _, e := range hook.AllEntries() {
			msgs = append(msgs, fmt.Sprintf("[%s] %s", e.Level, e.Message))
		}
		t.Fatalf("expected warning mentioning API ID and version 3; got entries:\n  %s", strings.Join(msgs, "\n  "))
	}
	assert.Contains(t, found.Message, "@key", "warning should reference the @key directive that triggered it")
}

// TestGraphQLMiddleware_V3_Subscription_FederationSubgraph_TWS is the
// federation + subscription happy path. It loads Tyk with a federation API
// that has a subscription field returning an entity (`type User @key(...)`
// + `type Subscription { userCreated: User! }`), wires a graphql-transport-ws
// upstream subgraph that emits one User event, and asserts the event is
// delivered to the Tyk client with the federation entity's `__typename`
// preserved.
//
// Federation + subscription is a new combination for graphql-go-tools/v2 —
// upstream has zero direct test coverage for it. If this test fails for a
// reason other than the use-after-free we already fixed, capture the
// failure and treat it as a follow-up: do not try to chase planner gaps
// here. The test is intentionally narrow: a single subgraph, a single
// subscription field, a single event.
func TestGraphQLMiddleware_V3_Subscription_FederationSubgraph_TWS(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	cfg := g.Gw.GetConfig()
	cfg.HttpServerOptions.EnableWebSockets = true
	g.Gw.SetConfig(cfg)

	const tws = "graphql-transport-ws"

	upstreamUpgrader := websocket.Upgrader{
		Subprotocols: []string{tws},
		CheckOrigin:  func(r *http.Request) bool { return true },
	}
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upstreamUpgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upstream upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		_, initMsg, err := conn.ReadMessage()
		if err != nil || !strings.Contains(string(initMsg), `"type":"connection_init"`) {
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"connection_ack"}`)); err != nil {
			return
		}

		_, subMsg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		subID, _ := jsonparser.GetString(subMsg, "id")
		if subID == "" {
			return
		}
		next := fmt.Sprintf(`{"id":%q,"type":"next","payload":{"data":{"userCreated":{"__typename":"User","id":"u-1","username":"alice"}}}}`, subID)
		_ = conn.WriteMessage(websocket.TextMessage, []byte(next))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"id":%q,"type":"complete"}`, subID)))

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer upstreamServer.Close()

	// Federation v2 subgraph schema with a subscription. The middleware
	// runs BuildFederationSchema so the `_Entity` union, `_entities`, and
	// `_service` symbols are in place when the engine plans the operation.
	schema := `
		type Query { user: User }
		type User @key(fields: "id") {
			id: ID!
			username: String!
		}
		type Subscription { userCreated: User! }
	`

	g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = schema
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
				Name: "users_ds",
				RootFields: []apidef.GraphQLTypeFields{
					{Type: "Query", Fields: []string{"user"}},
					{Type: "Subscription", Fields: []string{"userCreated"}},
				},
				Config: []byte(fmt.Sprintf(`{
					"url": %q,
					"method": "POST"
				}`, upstreamServer.URL)),
			},
		}
	})

	baseURL := strings.Replace(g.URL, "http://", "ws://", 1)

	clientConn, _, err := websocket.DefaultDialer.Dial(baseURL, http.Header{
		header.SecWebSocketProtocol: {tws},
	})
	require.NoError(t, err, "client dial Tyk")
	defer clientConn.Close()

	require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, clientConn.WriteMessage(websocket.TextMessage, []byte(`{"type":"connection_init"}`)))
	_, ackMsg, err := clientConn.ReadMessage()
	require.NoError(t, err, "client read connection_ack")
	require.Contains(t, string(ackMsg), `"type":"connection_ack"`)

	const subID = "sub-fed"
	subFrame := fmt.Sprintf(`{"id":%q,"type":"subscribe","payload":{"query":"subscription { userCreated { __typename id username } }"}}`, subID)
	require.NoError(t, clientConn.WriteMessage(websocket.TextMessage, []byte(subFrame)))

	var (
		gotNext     bool
		gotComplete bool
		nextPayload []byte
	)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (!gotNext || !gotComplete) {
		require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(2*time.Second)))
		_, msg, err := clientConn.ReadMessage()
		if err != nil {
			t.Fatalf("client read failed (gotNext=%v complete=%v): %v", gotNext, gotComplete, err)
		}
		typ, _ := jsonparser.GetString(msg, "type")
		switch typ {
		case "next":
			gotNext = true
			nextPayload = append([]byte(nil), msg...)
		case "complete":
			gotComplete = true
		case "error":
			// Federation+subscription planner gaps in graphql-go-tools/v2
			// surface here; capture the full payload so the follow-up has
			// signal to work from.
			t.Fatalf("subscription returned error frame: %s", string(msg))
		}
	}

	require.True(t, gotNext, "client must receive a next frame")
	typename, _ := jsonparser.GetString(nextPayload, "payload", "data", "userCreated", "__typename")
	assert.Equal(t, "User", typename, "next frame must preserve the federation entity __typename; got: %s", string(nextPayload))
	assert.True(t, gotComplete, "client must receive a complete frame")
}

// TestGraphQLMiddleware_V3_Subscription_ProxyMode_FederationPassthrough_TWS
// covers the federation-passthrough subscription path: Tyk runs in
// proxy-only mode in front of an existing federation subgraph. The customer
// SDL declares `@key` plus a Subscription type, the schema is auto-augmented
// with the federation extensions (proxy-mode passthrough), and the WS proxy
// forwards the entire `graphql-transport-ws` exchange to the upstream
// verbatim.
//
// The mock upstream signals (via a channel) that it actually saw the
// `subscribe` frame at its WebSocket handler — proving Tyk's proxy-only
// pipeline routed the subscription through to the upstream rather than
// terminating it at the gateway.
func TestGraphQLMiddleware_V3_Subscription_ProxyMode_FederationPassthrough_TWS(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	cfg := g.Gw.GetConfig()
	cfg.HttpServerOptions.EnableWebSockets = true
	g.Gw.SetConfig(cfg)

	const tws = "graphql-transport-ws"

	subscribeSeen := make(chan string, 1)

	upstreamUpgrader := websocket.Upgrader{
		Subprotocols: []string{tws},
		CheckOrigin:  func(r *http.Request) bool { return true },
	}
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HTTP query path — the proxy-only mode always serves regular queries
		// over plain HTTP. We don't exercise this path here, but a 200 keeps
		// any introspection or `_service { sdl }` probe happy.
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{}}`))
			return
		}

		conn, err := upstreamUpgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upstream upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		_, initMsg, err := conn.ReadMessage()
		if err != nil || !strings.Contains(string(initMsg), `"type":"connection_init"`) {
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"connection_ack"}`)); err != nil {
			return
		}

		_, subMsg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		subID, _ := jsonparser.GetString(subMsg, "id")
		if subID == "" {
			return
		}
		// Surface the subscribe to the test goroutine so we can assert that
		// the proxy actually carried the frame upstream.
		select {
		case subscribeSeen <- string(subMsg):
		default:
		}

		// Emit two events, then complete.
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(
			`{"id":%q,"type":"next","payload":{"data":{"userCreated":{"__typename":"User","id":"u-1","username":"alice"}}}}`,
			subID,
		)))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(
			`{"id":%q,"type":"next","payload":{"data":{"userCreated":{"__typename":"User","id":"u-2","username":"bob"}}}}`,
			subID,
		)))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"id":%q,"type":"complete"}`, subID)))

		// Drain client closes.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer upstreamServer.Close()

	// Customer SDL: federation-keyed entity plus a subscription. Schema
	// augmentation injects `_entities`, `_service`, etc. before validation
	// (see mw_graphql.go schemaHasKeyDirective branch).
	schema := `
		type Query { user(id: ID!): User }
		type User @key(fields: "id") {
			id: ID!
			username: String!
		}
		type Subscription { userCreated: User! }
	`

	g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstreamServer.URL
		spec.GraphQL.Enabled = true
		spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
		spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
		spec.GraphQL.Schema = schema
		// Leave Proxy.SubscriptionType empty — V3's flipped default
		// selects `graphql-transport-ws` for proxy-only too.
	})

	baseURL := strings.Replace(g.URL, "http://", "ws://", 1)

	clientConn, _, err := websocket.DefaultDialer.Dial(baseURL, http.Header{
		header.SecWebSocketProtocol: {tws},
	})
	require.NoError(t, err, "client dial Tyk")
	defer clientConn.Close()

	require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, clientConn.WriteMessage(websocket.TextMessage, []byte(`{"type":"connection_init"}`)))
	_, ackMsg, err := clientConn.ReadMessage()
	require.NoError(t, err, "client read connection_ack")
	require.Contains(t, string(ackMsg), `"type":"connection_ack"`)

	const subID = "sub-passthrough"
	subFrame := fmt.Sprintf(`{"id":%q,"type":"subscribe","payload":{"query":"subscription { userCreated { __typename id username } }"}}`, subID)
	require.NoError(t, clientConn.WriteMessage(websocket.TextMessage, []byte(subFrame)))

	// Confirm the upstream actually saw the subscribe frame within a
	// reasonable time. If proxy-mode terminated the WS at the gateway
	// instead of forwarding, this would time out.
	select {
	case got := <-subscribeSeen:
		assert.Contains(t, got, "userCreated", "upstream subscribe payload must carry the operation; got: %s", got)
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the subscribe frame — proxy did not forward")
	}

	var (
		users       []string
		gotComplete bool
	)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (len(users) < 2 || !gotComplete) {
		require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(2*time.Second)))
		_, msg, err := clientConn.ReadMessage()
		if err != nil {
			t.Fatalf("client read failed (users=%v complete=%v): %v", users, gotComplete, err)
		}
		typ, _ := jsonparser.GetString(msg, "type")
		switch typ {
		case "next":
			id, _ := jsonparser.GetString(msg, "payload", "data", "userCreated", "id")
			users = append(users, id)
		case "complete":
			gotComplete = true
		case "error":
			t.Fatalf("subscription returned error frame: %s", string(msg))
		}
	}

	assert.ElementsMatch(t, []string{"u-1", "u-2"}, users, "client must receive both User events")
	assert.True(t, gotComplete, "client must receive a complete frame")
}
