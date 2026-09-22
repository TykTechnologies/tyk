package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
	"github.com/stretchr/testify/assert"
)

func TestGraphQL_GranularAccess_ErrorOverride(t *testing.T) {
	g := StartTest(nil)
	t.Cleanup(g.Close)

	apis := g.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/api1"
			spec.UseKeylessAccess = false
			spec.GraphQL.Enabled = true
			spec.GraphQL.Schema = `
				type Query { accounts: [Account] }
				type Account { id: ID! name: String secretKey: String }
			`
			spec.ErrorOverrides = apidef.ErrorOverridesMap{
				"400": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: http.StatusForbidden,
							Body:       `{"errors":[{"message":"Access denied"}]}`,
						},
					},
				},
			}
		},
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/api2"
			spec.UseKeylessAccess = false
			spec.GraphQL.Enabled = true
			spec.GraphQL.Schema = `
				type Query { accounts: [Account] }
				type Account { id: ID! name: String secretKey: String }
			`
		},
	)

	api1 := apis[0]
	api2 := apis[1]

	_, directKey := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api1.APIID: {
				APIID:   api1.APIID,
				APIName: api1.Name,
				RestrictedTypes: []graphql.Type{
					{
						Name:   "Account",
						Fields: []string{"secretKey"},
					},
				},
			},
			api2.APIID: {
				APIID:   api2.APIID,
				APIName: api2.Name,
				RestrictedTypes: []graphql.Type{
					{
						Name:   "Account",
						Fields: []string{"secretKey"},
					},
				},
			},
		}
	})

	t.Run("Requesting secured field makes server to respond mapped error", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{
			Path: "/api1",
			Data: graphql.Request{
				Query: "query { accounts { id name secretKey } }",
			},
			Headers: map[string]string{
				header.Authorization: directKey,
			},
			Code: http.StatusForbidden,
			BodyMatchFunc: func(bytes []byte) bool {
				return string(bytes) == `{"errors":[{"message":"Access denied"}]}`
			},
		})
	})

	t.Run("Requesting allowed fields makes server respond 200 Ok", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{
			Path: "/api1",
			Data: graphql.Request{
				Query: "query { accounts { id name } }",
			},
			Headers: map[string]string{
				header.Authorization: directKey,
			},
			Code: http.StatusOK,
		})
	})

	t.Run("Requesting secured field without error overrides responds original 400 error", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{
			Path: "/api2",
			Data: graphql.Request{
				Query: "query { accounts { id name secretKey } }",
			},
			Headers: map[string]string{
				header.Authorization: directKey,
			},
			Code: http.StatusBadRequest,
			BodyMatchFunc: func(bytes []byte) bool {
				return assert.Contains(t, string(bytes), `{"errors":[{"message":"field: secretKey is restricted on type: Account"}]}`)
			},
		})
	})
}
