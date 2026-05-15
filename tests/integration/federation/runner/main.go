// Command runner is an in-process Tyk gateway harness used by the
// scenario scripts under tests/integration/federation. It mirrors the
// setup used in gateway/mw_graphql_federation_test.go: it boots a real
// gateway via gateway.StartTest(nil), builds an API spec via
// gateway.BuildAPI(...) and loads it via Gw.LoadAPI(spec). It also
// stands up a mock upstream when the chosen scenario needs one.
//
// The runner prints two contracts on stdout that scenario scripts parse:
//
//	TYK_URL=<gateway base url>
//	MOCK_URL=<mock upstream base url, optional>
//	READY
//
// After "READY" the runner blocks until SIGINT/SIGTERM, at which point
// it shuts the gateway down cleanly.
//
// This binary lives in its own Go module so the parent Tyk module's
// build (`go build ./...`) doesn't try to compile a binary that pulls
// in the test-only gateway.StartTest helper.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
)

func main() {
	scenario := flag.String("scenario", "rest", "scenario to run: rest|hasura|proxy|edge|partial-failure")
	listenPath := flag.String("listen-path", "/", "Tyk listen path for the loaded API")
	flag.Parse()

	t := gateway.StartTest(nil)
	defer t.Close()

	mockURL, configure, err := buildScenario(*scenario)
	if err != nil {
		log.Fatalf("scenario %q: %v", *scenario, err)
	}

	specs := gateway.BuildAPI(func(spec *gateway.APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = *listenPath
		configure(spec)
	})
	t.Gw.LoadAPI(specs[0])

	fmt.Printf("TYK_URL=%s%s\n", t.URL, *listenPath)
	if mockURL != "" {
		fmt.Printf("MOCK_URL=%s\n", mockURL)
	}
	fmt.Println("READY")
	// Force a flush so scenario scripts that do `grep -m1 ^READY` don't
	// race with the gateway buffering on a non-tty stdout.
	_ = os.Stdout.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}

// buildScenario returns a mock upstream URL (empty if none is needed)
// and a function that fills out the API spec for the chosen scenario.
func buildScenario(scenario string) (string, func(*gateway.APISpec), error) {
	switch scenario {
	case "rest", "partial-failure":
		// REST upstream returning users by id; 404 for unknown ids so the
		// partial-failure scenario can drive both the success and the
		// per-entity-failure paths from the same runner.
		mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/users/1":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"1","username":"alice"}`))
			case "/users/2":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"2","username":"bob"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		mockURL := mock.URL
		return mockURL, func(spec *gateway.APISpec) {
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
			spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
			spec.GraphQL.Schema = userKeyedSchema
			spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
				{
					Kind: apidef.GraphQLEngineDataSourceKindREST,
					Name: "user_ds",
					RootFields: []apidef.GraphQLTypeFields{
						{Type: "User", Fields: []string{"id", "username"}},
					},
					Config: []byte(fmt.Sprintf(`{"url":"%s/users/{{ .object.id }}","method":"GET"}`, mockURL)),
				},
			}
		}, nil

	case "hasura":
		// GraphQL upstream that does NOT advertise federation but does
		// support introspection and a `user(id: ID!): User` lookup. Tyk's
		// auto-detect picks the generated-lookup strategy here.
		mock := newHasuraMock()
		return mock.URL, func(spec *gateway.APISpec) {
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeExecutionEngine
			spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
			spec.GraphQL.Schema = userKeyedSchema
			spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
				{
					Kind: apidef.GraphQLEngineDataSourceKindGraphQL,
					Name: "user_ds",
					RootFields: []apidef.GraphQLTypeFields{
						{Type: "User", Fields: []string{"id", "username"}},
					},
					Config: []byte(fmt.Sprintf(`{"url":%q,"method":"POST"}`, mock.URL)),
				},
			}
		}, nil

	case "proxy":
		// Tyk in proxyOnly mode in front of an existing federated subgraph.
		// By default we stand up a local mock that answers
		// `_service { sdl }` and `_entities` itself. If the caller sets
		// TYK_PROXY_TARGET (used by scenario 05 to point Tyk at the Python
		// stub), we use that instead so a single supergraph can have Tyk
		// in front of a different real subgraph.
		target := os.Getenv("TYK_PROXY_TARGET")
		mockURL := ""
		if target == "" {
			mock := newFederatedSubgraphMock()
			target = mock.URL
			mockURL = mock.URL
		}
		// Choose the local validation schema based on whether we're
		// fronting the local User mock or an external (typically Post-
		// owning) subgraph. The local schema is what Tyk uses to
		// validate incoming queries before forwarding; `_service`
		// passes through the upstream SDL regardless.
		schema := userKeyedSchema
		if os.Getenv("TYK_PROXY_TARGET") != "" {
			schema = postKeyedSchema
		}
		return mockURL, func(spec *gateway.APISpec) {
			spec.Proxy.TargetURL = target
			spec.GraphQL.Enabled = true
			spec.GraphQL.ExecutionMode = apidef.GraphQLExecutionModeProxyOnly
			spec.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
			spec.GraphQL.Schema = schema
		}, nil

	case "edge":
		// Tyk as an edge proxy in front of Apollo Router (or any GraphQL
		// endpoint). No GraphQL config — Tyk just rate-limits / authenticates
		// and passes the request through. The scenario script wires the
		// proxy target to whatever it spins up.
		//
		// The scenario script is responsible for setting TYK_PROXY_TARGET in
		// the environment before starting this runner; we read it here so
		// the runner doesn't need to know about Apollo Router lifecycle.
		target := os.Getenv("TYK_PROXY_TARGET")
		if target == "" {
			target = "http://127.0.0.1:4000"
		}
		return "", func(spec *gateway.APISpec) {
			spec.Proxy.TargetURL = target
			// No GraphQL block: behaves like a normal HTTP proxy.
		}, nil

	default:
		return "", nil, fmt.Errorf("unknown scenario %q (want rest|hasura|proxy|edge|partial-failure)", scenario)
	}
}

// userKeyedSchema is the customer-facing SDL used by every UDG and proxy
// scenario where Tyk owns the User entity. Federation v2 @link is
// auto-prepended by Tyk at SDL emit time.
const userKeyedSchema = `
	type User @key(fields: "id") {
		id: ID!
		username: String!
	}
	type Query {
		user(id: ID!): User
	}
`

// postKeyedSchema is used by the proxy scenario when Tyk is fronting an
// external Posts subgraph (e.g. scenario 05's "Tyk in both positions"
// reproducer). The shape mirrors what the Python stub-subgraph exposes
// so Tyk can validate `_entities` queries with Post representations
// before forwarding them upstream.
const postKeyedSchema = `
	type Post @key(fields: "id") {
		id: ID!
		title: String!
		author: User!
	}
	type User @key(fields: "id") {
		id: ID!
	}
	type Query {
		posts: [Post!]!
		postById(id: ID!): Post
	}
`

// newHasuraMock stands up a non-federation GraphQL upstream that answers
// introspection + a `user(id: ID!): User` lookup, but rejects
// `_service { sdl }` with a standard "Cannot query field" error.
func newHasuraMock() *httptest.Server {
	const introspection = `{
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
									{"name": "id", "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}}}
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

	type gqlReq struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req gqlReq
		_ = json.Unmarshal(body, &req)

		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "_service"):
			_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"_service\" on type \"Query\"."}]}`))
		case strings.Contains(req.Query, "__schema"):
			_, _ = w.Write([]byte(introspection))
		case strings.Contains(req.Query, "user("):
			id, _ := req.Variables["k"].(string)
			if id == "" {
				_, _ = w.Write([]byte(`{"data":{"user":null}}`))
				return
			}
			username := "alice"
			if id == "2" {
				username = "bob"
			}
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"data":{"user":{"__typename":"User","id":%q,"username":%q}}}`, id, username,
			)))
		default:
			http.Error(w, "unexpected query: "+req.Query, http.StatusBadRequest)
		}
	}))
}

// newFederatedSubgraphMock stands up a tiny federation v2 subgraph that
// answers _service { sdl } and _entities directly, suitable for the
// proxy-mode passthrough scenario.
func newFederatedSubgraphMock() *httptest.Server {
	const upstreamSDL = `extend schema @link(url: "https://specs.apollo.dev/federation/v2.5", import: ["@key"])
type User @key(fields: "id") { id: ID! username: String! }`

	type gqlReq struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req gqlReq
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "_service"):
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"_service":{"sdl":%q}}}`, upstreamSDL)))
		case strings.Contains(req.Query, "_entities"):
			// Echo the representations back as concrete User rows. Real
			// subgraphs would look up the data; this mock is just enough
			// for the proxy scenario to round-trip an _entities request.
			reps, _ := req.Variables["representations"].([]any)
			out := make([]map[string]any, 0, len(reps))
			for _, rep := range reps {
				m, _ := rep.(map[string]any)
				if m == nil {
					out = append(out, nil)
					continue
				}
				id, _ := m["id"].(string)
				username := "alice"
				if id == "2" {
					username = "bob"
				}
				out = append(out, map[string]any{
					"__typename": "User",
					"id":         id,
					"username":   username,
				})
			}
			payload, _ := json.Marshal(map[string]any{"data": map[string]any{"_entities": out}})
			_, _ = w.Write(payload)
		default:
			http.Error(w, "unexpected query: "+req.Query, http.StatusBadRequest)
		}
	}))
}
