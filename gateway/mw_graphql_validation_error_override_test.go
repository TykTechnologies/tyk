package gateway

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

const tt18531Schema = `
	type Query { accounts: [Account] account(id: ID!): Account }
	type Account { id: ID! name: String secretKey: String }
`

const tt18531OverrideBody = `{"errors":[{"message":"Access denied"}]}`

// TestGraphQL_ValidationError_ErrorOverride_TT_18531 covers normalization, validation and
// variable validation failures: with a 400 override the override wins, without it the
// engine's own GraphQL error body is returned unchanged.
func TestGraphQL_ValidationError_ErrorOverride_TT_18531(t *testing.T) {
	versions := []struct {
		name                     string
		version                  apidef.GraphQLConfigVersion
		expectedUnknownFieldBody string
	}{
		{
			name:                     "engine v2",
			version:                  apidef.GraphQLConfigVersion2,
			expectedUnknownFieldBody: `{"errors":[{"message":"field: foo not defined on type: Account","path":["query","accounts","foo"]}]}`,
		},
		{
			name:                     "engine v3",
			version:                  apidef.GraphQLConfigVersion3Preview,
			expectedUnknownFieldBody: `{"errors":[{"message":"field: foo not defined on type: Account","path":["query","accounts","foo"]}],"data":null}`,
		},
	}

	requests := []struct {
		name string
		req  graphql.Request
	}{
		{name: "unknown field", req: graphql.Request{Query: "query { accounts { foo } }"}},
		{name: "syntax error", req: graphql.Request{Query: "query { accounts { id "}},
		{name: "invalid variables", req: graphql.Request{
			Query:     "query($id: ID!) { account(id: $id) { id } }",
			Variables: json.RawMessage(`{"id": null}`),
		}},
	}

	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			g := StartTest(nil)
			t.Cleanup(g.Close)

			g.Gw.BuildAndLoadAPI(
				func(spec *APISpec) {
					spec.Proxy.ListenPath = "/override"
					spec.UseKeylessAccess = true
					spec.GraphQL.Enabled = true
					spec.GraphQL.Version = v.version
					spec.GraphQL.Schema = tt18531Schema
					spec.ErrorOverrides = apidef.ErrorOverridesMap{
						"400": []apidef.ErrorOverride{{
							Response: apidef.ErrorResponse{
								StatusCode: http.StatusForbidden,
								Body:       tt18531OverrideBody,
							},
						}},
					}
				},
				func(spec *APISpec) {
					spec.Proxy.ListenPath = "/plain"
					spec.UseKeylessAccess = true
					spec.GraphQL.Enabled = true
					spec.GraphQL.Version = v.version
					spec.GraphQL.Schema = tt18531Schema
				},
			)

			for _, rq := range requests {
				t.Run("override: "+rq.name, func(t *testing.T) {
					_, _ = g.Run(t, test.TestCase{
						Method: http.MethodPost,
						Path:   "/override",
						Data:   rq.req,
						Code:   http.StatusForbidden,
						BodyMatchFunc: func(body []byte) bool {
							if string(body) != tt18531OverrideBody {
								t.Logf("body: %s", body)
								return false
							}
							return true
						},
					})
				})

				t.Run("no override: "+rq.name, func(t *testing.T) {
					_, _ = g.Run(t, test.TestCase{
						Method: http.MethodPost,
						Path:   "/plain",
						Data:   rq.req,
						Code:   http.StatusBadRequest,
						BodyMatchFunc: func(body []byte) bool {
							var parsed struct {
								Errors []json.RawMessage `json:"errors"`
							}
							if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Errors) == 0 {
								t.Logf("not a single GraphQL error document: %s", body)
								return false
							}
							if rq.name == "unknown field" && string(body) != v.expectedUnknownFieldBody {
								t.Logf("body: %s", body)
								return false
							}
							return true
						},
					})
				})
			}
		})
	}
}
