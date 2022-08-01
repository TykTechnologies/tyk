package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestGraphQL_RestrictedTypes(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.GraphQL.Enabled = true
	})[0]

	_, directKey := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				RestrictedTypes: []graphql.Type{
					{
						Name:   "Country",
						Fields: []string{"code"},
					},
				},
			},
		}
	})

	pID := g.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				RestrictedTypes: []graphql.Type{
					{
						Name:   "Country",
						Fields: []string{"name"},
					},
				},
			},
		}
	})

	_, policyAppliedKey := g.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{pID}
	})

	t.Run("Direct key", func(t *testing.T) {
		authHeaderWithDirectKey := map[string]string{
			headers.Authorization: directKey,
		}

		restrictedQuery := graphql.Request{
			Query: "query Query { countries { code } }",
		}

		unrestrictedQuery := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    restrictedQuery,
				Headers: authHeaderWithDirectKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), `{"errors":[{"message":"field: code is restricted on type: Country"}]}`)
				},
				Code: http.StatusBadRequest,
			},
			{Data: unrestrictedQuery, Headers: authHeaderWithDirectKey, Code: http.StatusOK},
		}...)
	})

	t.Run("Policy applied key", func(t *testing.T) {
		test.Flaky(t) // TODO: TT-5220

		authHeaderWithPolicyAppliedKey := map[string]string{
			headers.Authorization: policyAppliedKey,
		}

		restrictedQuery := graphql.Request{
			Query: "query Query { countries { name } }",
		}

		unrestrictedQuery := graphql.Request{
			Query: "query Query { countries { code } }",
		}

		_, _ = g.Run(t, []test.TestCase{
			{
				Data:    restrictedQuery,
				Headers: authHeaderWithPolicyAppliedKey,
				BodyMatchFunc: func(bytes []byte) bool {
					return assert.Contains(t, string(bytes), `{"errors":[{"message":"field: name is restricted on type: Country"}]}`)
				},
				Code: http.StatusBadRequest,
			},
			{Data: unrestrictedQuery, Headers: authHeaderWithPolicyAppliedKey, Code: http.StatusOK},
		}...)
	})
}
