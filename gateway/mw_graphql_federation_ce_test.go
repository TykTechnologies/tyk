//go:build !ee && !dev

package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

// TestGraphQLMiddleware_FederationIgnoredInCE is the symmetric CE coverage for
// the EE-only Apollo Federation v2 augmentation step. The setup mirrors
// TestGraphQLMiddleware_UDGFederation_ServiceQuery (UDG, V3 Preview, schema
// declaring `@key` on `User`) so any drift between the EE and CE paths shows
// up here. The assertions are inverted: the CE stub MUST NOT augment the
// schema, MUST emit a warning pointing at the EE build, and `{ _service { sdl } }`
// MUST fail with "field not defined on type Query" rather than succeed —
// because in CE `_service` is not a Query field.
//
// This is the federation analogue of the streams 403 stub: a CE customer who
// declares `@key` shouldn't crash the API; they should get an audible warning
// and federation queries should land in an obvious "not supported" state.
func TestGraphQLMiddleware_FederationIgnoredInCE(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	// `go test` without TYK_LOGLEVEL clamps the gateway logger to ErrorLevel
	// (see gateway/server.go), which would suppress our Warn. Lift it for
	// the duration of this test so the warning is observable. Mirrors the
	// EE V2WithKeyDirective_LogsWarning pattern.
	prevLevel := log.GetLevel()
	log.SetLevel(logrus.WarnLevel)
	t.Cleanup(func() { log.SetLevel(prevLevel) })

	hook := &logrustest.Hook{}
	log.AddHook(hook)
	t.Cleanup(func() {
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

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	const apiID = "ce-federation-ignored-api"
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
		spec.APIID = apiID
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

	// Loading the API must succeed: CE simply skips the augmentation, it
	// doesn't reject the spec. The customer's `@key` SDL is preserved
	// verbatim and the API is otherwise fully functional for non-federation
	// queries.
	g.Gw.LoadAPI(spec)

	// Assert the warning fired. The CE stub emits a Warnf via the
	// `schemaHasKeyDirective` branch in mw_graphql_federation.go pointing
	// the customer at the EE build.
	var foundWarning bool
	for _, entry := range hook.AllEntries() {
		if entry.Level != logrus.WarnLevel {
			continue
		}
		if !strings.Contains(entry.Message, apiID) {
			continue
		}
		if !strings.Contains(entry.Message, "Apollo Federation v2") {
			continue
		}
		if !strings.Contains(entry.Message, "EE") {
			continue
		}
		foundWarning = true
		break
	}
	assert.True(t, foundWarning, "expected a CE warning about Apollo Federation v2 + EE for API %s; got entries: %#v", apiID, hook.AllEntries())

	// Drive a `_service { sdl }` query through the live request pipeline.
	// Without augmentation, `_service` is not a Query field — the response
	// must surface a GraphQL error AND `data._service.sdl` must NOT be
	// reachable.
	res, err := g.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/",
		Data:   `{"query": "{ _service { sdl } }"}`,
	})
	require.NoError(t, err)
	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	res.Body.Close()
	bodyStr := string(resBody)

	// `_service` is not a Query field in CE because the schema was never
	// augmented. The graphql validator returns a 400 with an `errors`
	// envelope; the exact wording matches what was historically returned
	// before the EE augmentation existed.
	assert.NotContains(t, bodyStr, `"sdl":`, "CE response must not contain a resolved _service.sdl; got: %s", bodyStr)
	assert.Contains(t, bodyStr, `"errors"`, "CE response must surface a GraphQL `errors` envelope for `_service` queries; got: %s", bodyStr)
	assert.Contains(t, strings.ToLower(bodyStr), "_service", "errors envelope must reference the rejected _service field; got: %s", bodyStr)
}
